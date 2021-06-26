#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "include/modern-coapp.hpp"

TEST_CASE( "Empty PDU should fail to parse", "[parse]" ) {
    REQUIRE_THROWS( coapp::pdu::from({}) );
}

TEST_CASE( "PDU with invalid header should fail to parse", "[parse]" ) {
    uint8_t header = 0b11000000u;  // Ver: 3, Type: 0, TKL: 0
    std::vector<uint8_t> raw_pdu = {
        header, 0, 0, 0
    };
    REQUIRE_THROWS( coapp::pdu::from(std::move(raw_pdu)) );

    header = 0b01001001u; // Ver: 1, Type: 0, TKL: 9
    raw_pdu = {
        header, 0, 0, 0
    };
    REQUIRE_THROWS( coapp::pdu::from(std::move(raw_pdu)) );
}

TEST_CASE( "PDU with valid header should parse correctly", "[parse]" ) {
    uint8_t header = 0b01101000u;  // Ver: 1, Type: 2, TKL: 8
    std::vector<uint8_t> raw_pdu = {
        header,
        2,   // Code
        1,0, // MID: 0000 0001 0000 0000 => 256
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    auto pdu = coapp::pdu::from(std::move(raw_pdu));
    REQUIRE( pdu.version() == 1 );
    REQUIRE( pdu.type() == 2 );
    REQUIRE( pdu.message_id() == 256 );
    REQUIRE( pdu.code() == 2 );
    REQUIRE( pdu.token() == std::vector<uint8_t> { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 } );
}

TEST_CASE( "PDU with payload should parse correctly", "[parse]" ) {
    uint8_t header = 0b01101000u;  // Ver: 1, Type: 2, TKL: 8
    std::vector<uint8_t> raw_pdu = {
        header,
        2,   // Code
        1,0, // MID: 0000 0001 0000 0000 => 256
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Token
        0xff, // Payload separator
        0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41
    };

    auto pdu = coapp::pdu::from(raw_pdu);

    REQUIRE( pdu.payload_raw() == std::vector<uint8_t> { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 } );
    REQUIRE( pdu.payload() == "AAAAAAAAAAAAAA" );

    REQUIRE ( pdu.to_bytes() == raw_pdu );
}

TEST_CASE( "PDU with invalid options should fail to parse", "[parse]" ) {
    std::vector<uint8_t> raw_pdu = {
        0b01100000u,  // Ver: 1, Type: 2, TKL: 0
        2,   // Code
        1,0, // MID: 0000 0001 0000 0000 => 256
        0b00010001, // Option length == 1, but no value
    };

    REQUIRE_THROWS( coapp::pdu::from(std::move(raw_pdu)) );
}

TEST_CASE( "PDU with valid option should parse correctly", "[parse]" ) {
    std::vector<uint8_t> raw_pdu = {
        0b01100000u,  // Ver: 1, Type: 2, TKL: 0

        2,   // Code

        1,0, // MID: 0000 0001 0000 0000 => 256

        0b00010001, // Option delta = 1, Option length = 1
        0xff        // Option value = 0xff
    };

    auto pdu = coapp::pdu::from(raw_pdu);
    auto& options = pdu.options();

    REQUIRE (options.size() == 1);
    REQUIRE (options[0].number == 1);
    REQUIRE (options[0].value == std::vector<uint8_t> { 0xff });

    REQUIRE (pdu.to_bytes() == raw_pdu);
}

TEST_CASE( "[1] PDU with multiple options should parse correctly", "[parse]" ) {
    std::vector<uint8_t> raw_pdu = {
        0b01100000u,  // Ver: 1, Type: 2, TKL: 0

        2,   // Code

        1,0, // MID: 0000 0001 0000 0000 => 256

        0b00010001, // Option delta = 1, Option length = 1
        0xff,       // Option value = 0xff

        0b00010001, // Option delta = 1, Option length = 1
        0xff,       // Option value = 0xff

        0b00110011,       // Option delta = 3, Option length = 3
        0xff, 0xff, 0xff, // Option value = 0xff 0xff 0xff

        0xff, // Payload separator
        0x42, 0x42, 0x42, 0x42 // Payload
    };

    auto pdu = coapp::pdu::from(raw_pdu);
    auto& options = pdu.options();

    REQUIRE (options.size() == 3);

    REQUIRE (options[0].number == 1);
    REQUIRE (options[0].value == std::vector<uint8_t> { 0xff });

    REQUIRE (options[1].number == 2);
    REQUIRE (options[1].value == std::vector<uint8_t> { 0xff });

    REQUIRE (options[2].number == 5);
    REQUIRE (options[2].value == std::vector<uint8_t> { 0xff, 0xff, 0xff });

    REQUIRE (pdu.payload() == "BBBB");

    REQUIRE (pdu.to_bytes() == raw_pdu);
}

TEST_CASE( "[2] PDU with multiple options should parse correctly 2", "[parse]" ) {
    std::vector<uint8_t> raw_pdu = {
        0b01100000u,  // Ver: 1, Type: 2, TKL: 0

        2,   // Code

        1,0, // MID: 0000 0001 0000 0000 => 256

        0b00010001, // Option delta = 1, Option length = 1
        0xff,       // Option value = 0xff

        0b00010001, // Option delta = 1, Option length = 1
        0xff,       // Option value = 0xff

        0b00110011,       // Option delta = 3, Option length = 3
        0xff, 0xff, 0xff, // Option value = 0xff 0xff 0xff

        0b11010011,       // Option delta = 13, Option length = 3
        0xff,             // Option delta - 13 = 255 => Option delta = 268
        0xff, 0xff, 0xff, // Option value = 0xff 0xff 0xff

        0b11100011,       // Option delta = 14, Option length = 3
        0xff, 0xff,       // Option delta - 269 = 65535 => Option delta = 65804
        0xff, 0xff, 0xff, // Option value = 0xff 0xff 0xff

        0xff, // Payload separator
        0x42, 0x42, 0x42, 0x42 // Payload
    };

    auto pdu = coapp::pdu::from(raw_pdu);
    auto& options = pdu.options();

    REQUIRE (options.size() == 5);

    REQUIRE (options[0].number == 1);
    REQUIRE (options[0].value == std::vector<uint8_t> { 0xff });

    REQUIRE (options[1].number == 2);
    REQUIRE (options[1].value == std::vector<uint8_t> { 0xff });

    REQUIRE (options[2].number == 5);
    REQUIRE (options[2].value == std::vector<uint8_t> { 0xff, 0xff, 0xff });

    REQUIRE (options[3].number == 273);
    REQUIRE (options[3].value == std::vector<uint8_t> { 0xff, 0xff, 0xff });

    REQUIRE (options[4].number == 66077);
    REQUIRE (options[4].value == std::vector<uint8_t> { 0xff, 0xff, 0xff });

    REQUIRE (pdu.payload() == "BBBB");

    REQUIRE (pdu.to_bytes() == raw_pdu);
}

// Adapted from libcoap
TEST_CASE( "libcoap 1", "[parse]" ) {
    std::vector<uint8_t> raw_pdu = {
        0x62, 0x44, 0x12, 0x34, 0x00, 0x00, 0x8d, 0xf2,
        'c',  'o',  'a',  'p',  ':',  '/',  '/',  'e',
        'x',  'a',  'm',  'p',  'l',  'e',  '.',  'c',
        'o',  'm',  '/',  '1',  '2',  '3',  '4',  '5',
        '/',  '%',  '3',  'F',  'x',  'y',  'z',  '/',
        '3',  '0',  '4',  '8',  '2',  '3',  '4',  '2',
        '3',  '4',  '/',  '2',  '3',  '4',  '0',  '2',
        '3',  '4',  '8',  '2',  '3',  '4',  '/',  '2',
        '3',  '9',  '0',  '8',  '4',  '2',  '3',  '4',
        '-',  '2',  '3',  '/',  '%',  'A',  'B',  '%',
        '3',  '0',  '%',  'a',  'f',  '/',  '+',  '1',
        '2',  '3',  '/',  'h',  'f',  'k',  's',  'd',
        'h',  '/',  '2',  '3',  '4',  '8',  '0',  '-',
        '2',  '3',  '4',  '-',  '9',  '8',  '2',  '3',
        '5',  '/',  '1',  '2',  '0',  '4',  '/',  '2',
        '4',  '3',  '5',  '4',  '6',  '3',  '4',  '5',
        '3',  '4',  '5',  '2',  '4',  '3',  '/',  '0',
        '1',  '9',  '8',  's',  'd',  'n',  '3',  '-',
        'a',  '-',  '3',  '/',  '/',  '/',  'a',  'f',
        'f',  '0',  '9',  '3',  '4',  '/',  '9',  '7',
        'u',  '2',  '1',  '4',  '1',  '/',  '0',  '0',
        '0',  '2',  '/',  '3',  '9',  '3',  '2',  '4',
        '2',  '3',  '5',  '3',  '2',  '/',  '5',  '6',
        '2',  '3',  '4',  '0',  '2',  '3',  '/',  '-',
        '-',  '-',  '-',  '/',  '=',  '1',  '2',  '3',
        '4',  '=',  '/',  '0',  '9',  '8',  '1',  '4',
        '1',  '-',  '9',  '5',  '6',  '4',  '6',  '4',
        '3',  '/',  '2',  '1',  '9',  '7',  '0',  '-',
        '-',  '-',  '-',  '-',  '/',  '8',  '2',  '3',
        '6',  '4',  '9',  '2',  '3',  '4',  '7',  '2',
        'w',  'e',  'r',  'e',  'r',  'e',  'w',  'r',
        '0',  '-',  '9',  '2',  '1',  '-',  '3',  '9',
        '1',  '2',  '3',  '-',  '3',  '4',  '/',  0x0d,
        0x01, '/',  '/',  '4',  '9',  '2',  '4',  '0',
        '3',  '-',  '-',  '0',  '9',  '8',  '/',  0xc1,
        '*',  0xff, 'd',  'a',  't',  'a'
    };

    auto pdu = coapp::pdu::from(raw_pdu);

    REQUIRE (pdu.type() == 2);
    REQUIRE (pdu.message_id() == 0x1234);
    REQUIRE (pdu.token() == std::vector<uint8_t> { 0x0, 0x0 });

    auto& options = pdu.options();

    REQUIRE (options.size() == 3);
    REQUIRE (options[0].number == 8);
    REQUIRE (options[1].number == 8);
    REQUIRE (options[2].number == 20);

    const char* data0 = "coap://example.com/12345/%3Fxyz/3048234234/23402348234/239084234-23/%AB%30%af/+123/hfksdh/23480-234-98235/1204/243546345345243/0198sdn3-a-3///aff0934/97u2141/0002/3932423532/56234023/----/=1234=/098141-9564643/21970-----/82364923472wererewr0-921-39123-34/";
    const char* data1 = "//492403--098/";
    const char* data2 = "*";

    REQUIRE ( memcmp(data0, options[0].value.data(), options[0].value.size()) == 0 );
    REQUIRE ( memcmp(data1, options[1].value.data(), options[1].value.size()) == 0 );
    REQUIRE ( memcmp(data2, options[2].value.data(), options[2].value.size()) == 0 );

    REQUIRE (pdu.to_bytes() == raw_pdu);
}