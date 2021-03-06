#pragma once

#include <string_view>
#include <vector>

#define RESPONSE_CODE(Code)  ((((Code) / 100) << 5) | ((Code) % 100))
#define RESPONSE_CLASS(Code) ((Code) >> 5)

namespace coapp {

enum Type: uint8_t {
    Confirmable = 0,
    NonConfirmable,
    Acknowledgement,
    Reset
};

enum Method: uint8_t {
    GET = 1,
    POST,
    PUT,
    DELETE,
};

enum Code: uint8_t {
    Empty = 0,

    REQUEST_GET    = Method::GET,
    REQUEST_POST   = Method::POST,
    REQUEST_PUT    = Method::PUT,
    REQUEST_DELETE = Method::DELETE,

    RESPONSE_CREATED                    = RESPONSE_CODE(201),
    RESPONSE_DELETED                    = RESPONSE_CODE(202),
    RESPONSE_VALID                      = RESPONSE_CODE(203),
    RESPONSE_CHANGED                    = RESPONSE_CODE(204),
    RESPONSE_CONTENT                    = RESPONSE_CODE(205),
    RESPONSE_CONTINUE                   = RESPONSE_CODE(231),
    RESPONSE_BAD_REQUEST                = RESPONSE_CODE(400),
    RESPONSE_UNAUTHORIZED               = RESPONSE_CODE(401),
    RESPONSE_BAD_OPTION                 = RESPONSE_CODE(402),
    RESPONSE_FORBIDDEN                  = RESPONSE_CODE(403),
    RESPONSE_NOT_FOUND                  = RESPONSE_CODE(404),
    RESPONSE_NOT_ALLOWED                = RESPONSE_CODE(405),
    RESPONSE_NOT_ACCEPTABLE             = RESPONSE_CODE(406),
    RESPONSE_PRECONDITION_FAILED        = RESPONSE_CODE(412),
    RESPONSE_REQUEST_TOO_LARGE          = RESPONSE_CODE(413),
    RESPONSE_UNSUPPORTED_CONTENT_FORMAT = RESPONSE_CODE(415),
    RESPONSE_INTERNAL_SERVER_ERROR      = RESPONSE_CODE(500),
    RESPONSE_NOT_IMPLEMENTED            = RESPONSE_CODE(501),
    RESPONSE_BAD_GATEWAY                = RESPONSE_CODE(502),
    RESPONSE_SERVICE_UNAVAILABLE        = RESPONSE_CODE(503),
    RESPONSE_GATEWAY_TIMEOUT            = RESPONSE_CODE(504),
    RESPONSE_PROXYING_NOT_SUPPORTED     = RESPONSE_CODE(505),
};

enum Option {
    IfMatch =       1,
    UriHost =       3,
    ETag =          4,
    IfNoneMatch =   5,
    Observe =       6,
    UriPort =       7,
    LocationPath =  8,
    UriPath =       11,
    ContentFormat = 12,
    MaxAge =        14,
    UriQuery =      15,
    Accept =        17,
    LocationQuery = 20,
    Block2 =        23,
    Block1 =        27,
    Size2 =         28,
    Size1 =         60
};

class invalid_pdu : public std::exception {};

class pdu
{
public:
    using byte_t = uint8_t;
    using bytes_t = std::vector<byte_t>;

    using token_t = bytes_t;

    using option_number_t = uint32_t;
    using option_value_t = bytes_t;
    using options_t = std::multimap<option_number_t, option_value_t>;

    using payload_t = std::string;

    pdu() = default;

    static pdu from(bytes_t bytes)
    {
        /*

        PDU contains at least 4 bytes:

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Ver| T |  TKL  |      Code     |          Message ID           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        */
        if (bytes.size() < 4)
            throw invalid_pdu();

        pdu result;

        const auto& header = bytes[0];

        result._version = header >> 6;
        if (result._version != 1)
            throw invalid_pdu();

        result._type = static_cast<Type>((header & 0b00110000) >> 4);
        auto token_length = (header & 0b00001111);
        if (token_length > 8)
            throw invalid_pdu();

        result._code = static_cast<Code>(bytes[1]);
        result._message_id = (bytes[2] << 8) | (bytes[3]);

        // Parse token
        auto token_offset = bytes.begin() + 4;
        auto it = token_offset + token_length;

        if (it > bytes.end())
            throw invalid_pdu();

        result._token = { token_offset, it };

        if (it >= bytes.end())
            return result; // No options or payload

        // Parse options
        // Options and payload are separated by a FF byte
        option_number_t option_number = 0;
        while (it < bytes.end() && (*it) != 0xff) {
            // https://datatracker.ietf.org/doc/html/rfc7252#section-3.1

            uint32_t option_delta = *it >> 4;
            uint32_t option_length = *it & 0b00001111;

            auto parse_value = [&] (uint32_t& val) {
                if (val == 13)
                    val = 13 + *(++it);
                else if (val == 14)
                    val = 269 + ((*(++it) << 8) | (*(++it)));
                else if (val == 15)
                    throw invalid_pdu();
            };

            parse_value(option_delta);
            parse_value(option_length);

            it++;
            auto option_end = it + option_length;
            if (option_end > bytes.end())
                throw invalid_pdu();

            option_number += option_delta;
            result._options.emplace(std::make_pair(
                option_number,
                option_value_t { it, option_end }
            ));

            it = option_end;
        }

        if (it >= bytes.end())
            return result; // No payload

        // Skip the payload separator
        it++;

        // Rest of the PDU is payload
        result._payload = { it, bytes.end() };

        return result;
    }

    bytes_t to_bytes() const
    {
        auto required_size = 4; // header length
        required_size += _token.size();

        if (auto pl_size = _payload.size())
            required_size += 1 /* separator */ + pl_size;

        // Encode Options
        bytes_t options_buf;
        if (_options.size()) {
            // Try to minimize allocations, options will typically fit in 1024 bytes
            // (does not increase vector size)
            options_buf.reserve(1024);

            auto prev_delta = 0;
            for (const auto& [number, value]: _options) {
                auto option_delta = number - prev_delta;
                prev_delta = number;

                auto get_nibble = [&] (const uint32_t& val) -> uint8_t {
                    if (val < 13)
                        return val;
                    if (val < 269)
                        return 13;
                    return 14;
                };

                byte_t delta_nibble = get_nibble(option_delta);
                byte_t length_nibble = get_nibble(value.size());
                options_buf.push_back((delta_nibble << 4) | length_nibble);

                auto encode_val = [&] (const byte_t nibble, const uint32_t& val) {
                    if (nibble < 13)
                        return; // already encoded in nibble

                    if (nibble == 13) {
                        options_buf.push_back(val - 13);
                    } else if (nibble == 14) {
                        auto encoded_val = val - 269;
                        assert(encoded_val <= std::numeric_limits<uint16_t>::max());
                        options_buf.push_back(encoded_val >> 8);
                        options_buf.push_back(encoded_val);
                    }
                };
                encode_val(delta_nibble, option_delta);
                encode_val(length_nibble, value.size());

                std::copy(value.begin(), value.end(),
                          std::back_inserter(options_buf));
            }

            required_size += options_buf.size();
        }

        bytes_t bytes(required_size);

        // Header
        bytes[0] = (_version << 6) | (_type << 4) | _token.size();
        bytes[1] = _code;
        bytes[2] = _message_id >> 8;
        bytes[3] = _message_id;

        // Token
        auto it = bytes.begin() + 4;
        std::copy(_token.begin(), _token.end(), it);
        it += _token.size();

        // Options
        if (auto s = options_buf.size()) {
            std::move(options_buf.begin(), options_buf.end(), it);
            it += s;
        }

        // Payload
        if (_payload.size()) {
            *it = 0xff;
            std::copy(_payload.begin(), _payload.end(), ++it);
        }

        return bytes;
    }

    uint8_t version() const
    {
        return _version;
    }

    Type type() const
    {
        return _type;
    }

    Code code() const
    {
        return _code;
    }

    uint16_t message_id() const
    {
        return _message_id;
    }

    const token_t& token() const
    {
        return _token;
    }

    const options_t& options() const
    {
        return _options;
    }

    std::string_view payload() const
    {
        return _payload;
    }

    void set_type(Type type)
    {
        if (type > 3)
            throw invalid_pdu();

        _type = type;
    }

    void set_code(Code code)
    {
        _code = code;
    }

    void set_message_id(uint16_t mid)
    {
        _message_id = mid;
    }

    void set_token(bytes_t token)
    {
        if (token.size() > 8)
            throw invalid_pdu();

        _token = std::move(token);
    }

    void add_option(option_number_t number, option_value_t value)
    {
        _options.emplace(std::make_pair(number, std::move(value)));
    }

    void set_payload(payload_t payload)
    {
        _payload = std::move(payload);
    }

private:
    uint8_t _version { 1 };
    Type _type { 0 };

    Code _code { 0 };
    uint16_t _message_id { 0 };

    bytes_t _token;

    options_t _options;

    payload_t _payload;
};

}

#undef RESPONSE_CODE
#undef RESPONSE_CLASS