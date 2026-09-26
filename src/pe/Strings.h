#pragma once

// Printable string runs in a byte range, the way Sysinternals strings finds
// them: a run of printable ASCII, or a run of UTF-16LE code units whose high
// byte is zero and whose low byte is printable ASCII.

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace pemcp {

struct FoundString {
    std::uint64_t offset = 0; // of the first byte, relative to the scanned range's base
    std::uint32_t length = 0; // in characters, before any truncation
    bool wide = false;
    std::string text; // ASCII; at most maxTextLength characters
};

struct StringScan {
    std::size_t minLength = 5;
    bool ascii = true;
    bool wide = true;
    std::size_t maxTextLength = 200;
    std::size_t maxResults = 200000;
};

// Every run in `data`, sorted by offset. `base` is added to each offset.
[[nodiscard]] std::vector<FoundString> findStrings(std::span<const std::uint8_t> data, std::uint64_t base, const StringScan& scan);

} // namespace pemcp
