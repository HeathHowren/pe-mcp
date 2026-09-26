#include "pe/Strings.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace pemcp;

namespace {

std::vector<std::uint8_t> ascii(const std::string& s) {
    return {s.begin(), s.end()};
}

void appendWide(std::vector<std::uint8_t>& out, const std::string& s) {
    for (char c : s) {
        out.push_back(static_cast<std::uint8_t>(c));
        out.push_back(0);
    }
}

} // namespace

TEST_CASE("ASCII runs shorter than min_length are skipped", "[strings]") {
    const auto data = ascii(std::string("abcd\0hello\x01world!\0xy", 21));
    StringScan scan;
    scan.minLength = 5;
    scan.wide = false;
    const auto found = findStrings(data, 0x100, scan);
    REQUIRE(found.size() == 2);
    CHECK(found[0].text == "hello");
    CHECK(found[0].offset == 0x105);
    CHECK(found[1].text == "world!");
    CHECK(found[1].offset == 0x10B);
    CHECK_FALSE(found[0].wide);
}

TEST_CASE("UTF-16LE runs are found at either alignment", "[strings]") {
    std::vector<std::uint8_t> data = {0xFF};
    appendWide(data, "odd aligned");
    data.push_back(0);
    data.push_back(0);
    data.push_back(0);
    appendWide(data, "even aligned");
    StringScan scan;
    scan.ascii = false;
    const auto found = findStrings(data, 0, scan);
    REQUIRE(found.size() == 2);
    CHECK(found[0].text == "odd aligned");
    CHECK(found[0].offset == 1);
    CHECK(found[0].wide);
    CHECK(found[0].length == 11);
    CHECK(found[1].text == "even aligned");
    CHECK(found[1].offset == 26);
}

TEST_CASE("Both encodings together come back in offset order", "[strings]") {
    std::vector<std::uint8_t> data;
    appendWide(data, "wide first");
    data.push_back(0);
    data.push_back(0);
    for (char c : std::string("narrow second")) {
        data.push_back(static_cast<std::uint8_t>(c));
    }
    data.push_back(0);
    const auto found = findStrings(data, 0, StringScan{});
    REQUIRE(found.size() == 2);
    CHECK(found[0].wide);
    CHECK(found[0].text == "wide first");
    CHECK_FALSE(found[1].wide);
    CHECK(found[1].text == "narrow second");
}

TEST_CASE("Long strings are cut but report their full length", "[strings]") {
    const auto data = ascii(std::string(500, 'A'));
    StringScan scan;
    scan.maxTextLength = 200;
    const auto found = findStrings(data, 0, scan);
    REQUIRE(found.size() == 1);
    CHECK(found[0].text.size() == 200);
    CHECK(found[0].length == 500);
}

TEST_CASE("The result count is capped", "[strings]") {
    std::string text;
    for (int i = 0; i < 100; ++i) {
        text += "string";
        text += '\0';
    }
    StringScan scan;
    scan.maxResults = 10;
    CHECK(findStrings(ascii(text), 0, scan).size() == 10);
}

TEST_CASE("A string that runs to the end of the buffer is still reported", "[strings]") {
    const auto found = findStrings(ascii("\x01\x02tail string"), 0, StringScan{});
    REQUIRE(found.size() == 1);
    CHECK(found[0].text == "tail string");
    CHECK(findStrings({}, 0, StringScan{}).empty());
}
