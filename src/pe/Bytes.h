#pragma once

// Bounds-checked reads over a byte buffer.
//
// Every offset in a PE file is attacker-controlled in the sense that matters
// here: a truncated download or a hand-edited header puts any value in any
// field. So nothing in the reader indexes the buffer directly. It asks this
// view, which answers "no" for anything that would run past the end, and the
// caller turns that "no" into a sentence.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>

namespace pemcp {

class ByteView {
public:
    ByteView() = default;
    explicit ByteView(std::span<const std::uint8_t> data) : data_(data) {}

    [[nodiscard]] std::size_t size() const { return data_.size(); }
    [[nodiscard]] const std::uint8_t* data() const { return data_.data(); }

    // True when [offset, offset + length) lies inside the buffer. Written so
    // neither side can overflow, whatever the two values are.
    [[nodiscard]] bool contains(std::uint64_t offset, std::uint64_t length) const {
        return offset <= data_.size() && length <= data_.size() - offset;
    }

    template <typename T>
    [[nodiscard]] std::optional<T> read(std::uint64_t offset) const {
        if (!contains(offset, sizeof(T))) {
            return std::nullopt;
        }
        T value;
        std::memcpy(&value, data_.data() + offset, sizeof(T));
        return value;
    }

    // The bytes at [offset, offset + length), clipped to the end of the
    // buffer. An offset past the end gives an empty span.
    [[nodiscard]] std::span<const std::uint8_t> slice(std::uint64_t offset, std::uint64_t length) const {
        if (offset >= data_.size()) {
            return {};
        }
        const std::uint64_t available = data_.size() - offset;
        return data_.subspan(static_cast<std::size_t>(offset), static_cast<std::size_t>(length < available ? length : available));
    }

    // A NUL-terminated string of at most maxLength bytes. Returns nothing when
    // the terminator is not found within the limit or the buffer.
    [[nodiscard]] std::optional<std::string> cstring(std::uint64_t offset, std::size_t maxLength) const {
        const auto bytes = slice(offset, maxLength + 1);
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            if (bytes[i] == 0) {
                return std::string(reinterpret_cast<const char*>(bytes.data()), i);
            }
        }
        return std::nullopt;
    }

private:
    std::span<const std::uint8_t> data_;
};

// A name read out of a binary, made safe to put in JSON and in front of a
// model: printable ASCII is kept, anything else becomes '?'.
[[nodiscard]] inline std::string printable(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (char c : text) {
        const auto u = static_cast<unsigned char>(c);
        out += (u >= 0x20 && u < 0x7F) ? c : '?';
    }
    return out;
}

// "0x1A2B". Every address and offset pe-mcp returns is spelled this way.
[[nodiscard]] inline std::string hex(std::uint64_t value) {
    static constexpr char digits[] = "0123456789ABCDEF";
    char buffer[19];
    char* end = buffer + sizeof(buffer);
    char* p = end;
    do {
        *--p = digits[value & 0xF];
        value >>= 4;
    } while (value != 0);
    *--p = 'x';
    *--p = '0';
    return std::string(p, end);
}

// Bytes as contiguous uppercase hex, "4883EC28".
[[nodiscard]] inline std::string hexBytes(std::span<const std::uint8_t> bytes) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (std::uint8_t b : bytes) {
        out += digits[b >> 4];
        out += digits[b & 0xF];
    }
    return out;
}

} // namespace pemcp
