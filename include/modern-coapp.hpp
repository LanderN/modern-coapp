#pragma once

#include <string_view>
#include <vector>

namespace coapp {

class invalid_pdu : public std::exception {};

struct option
{
    uint32_t number { 0 };
    std::vector<uint8_t> value;
};

class pdu
{
public:
    pdu() = default;

    static pdu from(std::vector<uint8_t> bytes)
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

        result._type = (header & 0b00110000) >> 4;
        auto token_length = (header & 0b00001111);
        if (token_length > 8)
            throw invalid_pdu();

        result._code = bytes[1];
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
        uint32_t option_number = 0;
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
            result._options.emplace_back(option {
                option_number,
                { it, option_end }
            });

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

    // TODO: cleanup options encoding, there must be a better way
    std::vector<uint8_t> to_bytes() const
    {
        auto required_size = 4; // header length
        required_size += _token.size();

        if (auto pl_size = _payload.size())
            required_size += 1 /* separator */ + pl_size;

        auto prev_delta = 0;
        for (const auto& option: _options) {
            required_size += 1; // at least 1 byte

            auto option_delta = option.number - prev_delta;
            prev_delta = option.number;
            auto get_size = [&] (const uint32_t& val) {
                if (val < 13)
                    return 0;

                if (val < 269)
                    return 1;

                return 2;
            };
            required_size += get_size(option_delta);
            required_size += get_size(option.value.size());
            required_size += option.value.size();
        }

        std::vector<uint8_t> bytes(required_size);

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
        prev_delta = 0;
        for (const auto& option: _options) {

            auto option_delta = option.number - prev_delta;
            prev_delta = option.number;

            auto get_nibble = [&] (const uint32_t& val) -> uint8_t {
                if (val < 13)
                    return val;
                if (val < 269)
                    return 13;
                return 14;
            };

            uint8_t delta_nibble = get_nibble(option_delta);
            uint8_t length_nibble = get_nibble(option.value.size());
            *it = (delta_nibble << 4) | length_nibble;

            auto encode_val = [&] (const uint8_t nibble, const uint32_t& val) {
                if (nibble < 13)
                    return;

                if (nibble == 13) {
                    *(++it) = val - 13;
                } else if (nibble == 14) {
                    auto encoded_val = val - 269;
                    assert(encoded_val <= std::numeric_limits<uint16_t>::max());
                    *(++it) = encoded_val >> 8;
                    *(++it) = encoded_val;
                }
            };
            encode_val(delta_nibble, option_delta);
            encode_val(length_nibble, option.value.size());

            std::copy(option.value.begin(), option.value.end(), ++it);

            it += option.value.size();
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

    uint8_t type() const
    {
        return _type;
    }

    uint8_t code() const
    {
        return _code;
    }

    uint16_t message_id() const
    {
        return _message_id;
    }

    const std::vector<uint8_t>& token() const
    {
        return _token;
    }

    const std::vector<option>& options() const
    {
        return _options;
    }

    const std::vector<uint8_t>& payload_raw() const
    {
        return _payload;
    }

    std::string_view payload() const
    {
        static_assert(sizeof(uint8_t) == sizeof(char));
        return {
            reinterpret_cast<const char*>(_payload.data()),
            _payload.size()
        };
    }

    void set_type(uint8_t type)
    {
        if (type > 3)
            throw invalid_pdu();

        _type = type;
    }

    void set_token(std::vector<uint8_t> token)
    {
        if (token.size() > 8)
            throw invalid_pdu();

        _token = std::move(token);
    }

    void add_option(option opt)
    {
        _options.push_back(std::move(opt));
    }

    void set_payload(std::vector<uint8_t> payload)
    {
        _payload = std::move(payload);
    }

private:
    uint8_t _version { 1 };
    uint8_t _type { 0 };

    uint8_t _code { 0 };
    uint16_t _message_id { 0 };

    std::vector<uint8_t> _token;

    std::vector<option> _options;

    std::vector<uint8_t> _payload;
};

}