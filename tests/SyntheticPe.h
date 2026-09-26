#pragma once

// A PE file built byte by byte, so every RVA, name and reference in it is
// known exactly and the golden outputs do not move with the compiler.
//
// Layout (x64; x86 is the same except where noted):
//
//   headers   0x0000  SizeOfHeaders 0x400, e_lfanew 0x80
//   .text     RVA 0x1000, file 0x400, raw 0x200
//     0x1000  main: lea of the ASCII string, call through the
//             OutputDebugStringA slot, call 0x1040, read of .data 0x3000
//     0x1040  fixture_add (exported)
//     0x1050  the TLS callback
//     0x1060  a second use of the ASCII string, then jmp 0x1040
//   .rdata    RVA 0x2000, file 0x600, raw 0x400
//     0x2000  "Hello from the pe-mcp fixture"
//     0x2040  L"Wide fixture string"
//     0x2080  IAT: KERNEL32 OutputDebugStringA, GetTickCount
//     0x20A0  IAT: USER32 ordinal 7
//     0x2150  import descriptors
//     0x21A0  export directory: fixture_add, fixture_forward -> KERNEL32.Sleep
//     0x2240  TLS directory, callbacks at 0x2280
//     0x22A0  debug directory, CodeView record naming fixture.pdb
//     0x2300  unwind info (x64)
//   .data     RVA 0x3000, file 0xA00, raw 0x200, virtual size 0x1000
//     0x3000  a dword read by main; 0x3008 a pointer to fixture_add
//   .pdata    RVA 0x4000 (x64 only): four RUNTIME_FUNCTIONs, the last a
//             fragment chained to fixture_add
//   .rsrc     RVA 0x5000: TEXTFILE/#101/1033 and MANIFEST/#1/1033
//   overlay   16 bytes after the last section

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace synthetic {

[[nodiscard]] std::vector<std::uint8_t> build(bool is64);

// A PE with `count` distinct strings in .rdata, for paging and size-cap tests.
[[nodiscard]] std::vector<std::uint8_t> buildManyStrings(std::size_t count);

// File offsets of the structures the malformed-input tests aim at.
namespace offsets {
inline constexpr std::uint32_t ntHeaders = 0x80;
inline constexpr std::uint32_t sectionTable64 = 0x80 + 24 + 0xF0;
inline constexpr std::uint32_t sectionTable32 = 0x80 + 24 + 0xE0;
inline constexpr std::uint32_t rdata = 0x600; // file offset of RVA 0x2000
inline constexpr std::uint32_t rsrc64 = 0xE00; // file offset of RVA 0x5000 (x64)
} // namespace offsets

// Writes bytes to a unique file under the temp directory and deletes it when
// the object goes away.
class TempFile {
public:
    explicit TempFile(const std::vector<std::uint8_t>& bytes, const std::string& stem = "pemcp-test");
    ~TempFile();
    TempFile(const TempFile&) = delete;
    TempFile& operator=(const TempFile&) = delete;
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }
    [[nodiscard]] std::string utf8() const;

private:
    std::filesystem::path path_;
};

} // namespace synthetic
