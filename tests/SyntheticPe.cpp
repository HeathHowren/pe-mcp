#include "SyntheticPe.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <initializer_list>
#include <stdexcept>
#include <string_view>

#include <windows.h>

namespace synthetic {

namespace {

struct Sec {
    const char* name;
    std::uint32_t rva;
    std::uint32_t vsize;
    std::uint32_t raw;
    std::uint32_t rawSize;
    std::uint32_t flags;
};

constexpr std::uint32_t codeFlags = 0x60000020;  // code, execute, read
constexpr std::uint32_t rdataFlags = 0x40000040; // initialized data, read
constexpr std::uint32_t dataFlags = 0xC0000040;  // initialized data, read, write

class Image {
public:
    std::vector<std::uint8_t> file;
    std::vector<Sec> sections;

    void fileU16(std::size_t off, std::uint16_t v) { std::memcpy(&file.at(off), &v, 2); }
    void fileU32(std::size_t off, std::uint32_t v) { std::memcpy(&file.at(off), &v, 4); }
    void fileU64(std::size_t off, std::uint64_t v) { std::memcpy(&file.at(off), &v, 8); }

    std::size_t off(std::uint32_t rva) const {
        for (const Sec& s : sections) {
            if (rva >= s.rva && rva < s.rva + s.rawSize) {
                return s.raw + (rva - s.rva);
            }
        }
        throw std::logic_error("synthetic PE: RVA outside every section");
    }
    void put(std::uint32_t rva, std::initializer_list<std::uint8_t> bytes) {
        std::size_t o = off(rva);
        for (std::uint8_t b : bytes) {
            file.at(o++) = b;
        }
    }
    void u16(std::uint32_t rva, std::uint16_t v) { fileU16(off(rva), v); }
    void u32(std::uint32_t rva, std::uint32_t v) { fileU32(off(rva), v); }
    void u64(std::uint32_t rva, std::uint64_t v) { fileU64(off(rva), v); }
    void ptr(std::uint32_t rva, std::uint64_t v, bool is64) {
        if (is64) {
            u64(rva, v);
        } else {
            u32(rva, static_cast<std::uint32_t>(v));
        }
    }
    void str(std::uint32_t rva, std::string_view s) { // with its terminator
        std::size_t o = off(rva);
        for (char c : s) {
            file.at(o++) = static_cast<std::uint8_t>(c);
        }
        file.at(o) = 0;
    }
    void wstr(std::uint32_t rva, std::string_view s) {
        std::size_t o = off(rva);
        for (char c : s) {
            file.at(o++) = static_cast<std::uint8_t>(c);
            file.at(o++) = 0;
        }
        file.at(o) = 0;
        file.at(o + 1) = 0;
    }
};

// DOS header, COFF header, optional header and section table. Data
// directories are filled in afterwards through dir().
void writeHeaders(Image& img, bool is64, std::uint64_t imageBase) {
    img.file[0] = 'M';
    img.file[1] = 'Z';
    img.fileU32(0x3C, offsets::ntHeaders);
    const std::size_t nt = offsets::ntHeaders;
    img.fileU32(nt, 0x00004550);
    img.fileU16(nt + 4, is64 ? 0x8664 : 0x014C);
    img.fileU16(nt + 6, static_cast<std::uint16_t>(img.sections.size()));
    img.fileU32(nt + 8, 0x68D58A80); // 2025-09-25T18:31:28Z
    img.fileU16(nt + 20, is64 ? 0xF0 : 0xE0);
    img.fileU16(nt + 22, is64 ? 0x0022 : 0x0102);
    const std::size_t opt = nt + 24;
    img.fileU16(opt, is64 ? 0x20B : 0x10B);
    img.file[opt + 2] = 14;
    img.file[opt + 3] = 44;
    img.fileU32(opt + 16, 0x1000); // entry point
    img.fileU32(opt + 20, 0x1000); // base of code
    if (is64) {
        img.fileU64(opt + 24, imageBase);
    } else {
        img.fileU32(opt + 28, static_cast<std::uint32_t>(imageBase));
    }
    img.fileU32(opt + 32, 0x1000);
    img.fileU32(opt + 36, 0x200);
    img.fileU16(opt + 40, 6);
    img.fileU16(opt + 48, 6); // subsystem version
    img.fileU32(opt + 56, 0x6000);
    img.fileU32(opt + 60, 0x400);
    img.fileU16(opt + 68, 3);
    img.fileU16(opt + 70, is64 ? 0x8160 : 0x8140);
    img.fileU32(opt + (is64 ? 108 : 92), 16);
    std::size_t table = opt + (is64 ? 0xF0 : 0xE0);
    for (const Sec& s : img.sections) {
        std::memcpy(&img.file.at(table), s.name, std::strlen(s.name));
        img.fileU32(table + 8, s.vsize);
        img.fileU32(table + 12, s.rva);
        img.fileU32(table + 16, s.rawSize);
        img.fileU32(table + 20, s.raw);
        img.fileU32(table + 36, s.flags);
        table += 40;
    }
}

void dir(Image& img, bool is64, std::size_t index, std::uint32_t rva, std::uint32_t size) {
    const std::size_t at = offsets::ntHeaders + 24 + (is64 ? 112 : 96) + index * 8;
    img.fileU32(at, rva);
    img.fileU32(at + 4, size);
}

void writeCode64(Image& img) {
    img.put(0x1000, {0x48, 0x83, 0xEC, 0x28,                    // sub rsp, 0x28
                     0x48, 0x8D, 0x0D, 0xF5, 0x0F, 0x00, 0x00,  // lea rcx, [0x2000]
                     0xFF, 0x15, 0x6F, 0x10, 0x00, 0x00,        // call [0x2080]
                     0xB9, 0x01, 0x00, 0x00, 0x00,              // mov ecx, 1
                     0xE8, 0x25, 0x00, 0x00, 0x00,              // call 0x1040
                     0x8B, 0x05, 0xDF, 0x1F, 0x00, 0x00,        // mov eax, [0x3000]
                     0x48, 0x83, 0xC4, 0x28,                    // add rsp, 0x28
                     0xC3});                                    // ret
    img.put(0x1040, {0x8D, 0x04, 0x11, 0xC3});                  // lea eax, [rcx+rdx]; ret
    img.put(0x1050, {0xC3});                                    // TLS callback: ret
    img.put(0x1060, {0x48, 0x8D, 0x05, 0x99, 0x0F, 0x00, 0x00,  // lea rax, [0x2000]
                     0xE9, 0xD4, 0xFF, 0xFF, 0xFF});            // jmp 0x1040
}

void writeCode32(Image& img) {
    img.put(0x1000, {0x83, 0xEC, 0x1C,                          // sub esp, 0x1C
                     0x68, 0x00, 0x20, 0x40, 0x00,              // push 0x402000
                     0xFF, 0x15, 0x80, 0x20, 0x40, 0x00,        // call [0x402080]
                     0x6A, 0x01,                                // push 1
                     0xE8, 0x2B, 0x00, 0x00, 0x00,              // call 0x401040
                     0xA1, 0x00, 0x30, 0x40, 0x00,              // mov eax, [0x403000]
                     0x83, 0xC4, 0x1C,                          // add esp, 0x1C
                     0xC3});                                    // ret
    img.put(0x1040, {0x8B, 0x44, 0x24, 0x04, 0x03, 0x44, 0x24, 0x08, 0xC3}); // mov eax,[esp+4]; add eax,[esp+8]; ret
    img.put(0x1050, {0xC3});
    img.put(0x1060, {0xB8, 0x00, 0x20, 0x40, 0x00,              // mov eax, 0x402000
                     0xE9, 0xD6, 0xFF, 0xFF, 0xFF});            // jmp 0x401040
}

void writeRdata(Image& img, bool is64, std::uint64_t base) {
    const std::uint32_t ps = is64 ? 8 : 4;
    const std::uint64_t ordinalFlag = is64 ? (1ull << 63) : (1ull << 31);

    img.str(0x2000, "Hello from the pe-mcp fixture");
    img.wstr(0x2040, "Wide fixture string");

    // Hint/name entries and DLL names.
    img.u16(0x2100, 0);
    img.str(0x2102, "OutputDebugStringA");
    img.u16(0x2118, 1);
    img.str(0x211A, "GetTickCount");
    img.str(0x2130, "KERNEL32.dll");
    img.str(0x2140, "USER32.dll");

    // IAT at 0x2080 / 0x20A0 and the lookup tables at 0x20C0 / 0x20E0, with
    // the same contents, as a linker writes them before binding.
    for (std::uint32_t table : {0x2080u, 0x20C0u}) {
        img.ptr(table, 0x2100, is64);
        img.ptr(table + ps, 0x2118, is64);
        img.ptr(table + 0x20, ordinalFlag | 7, is64);
    }

    // Import descriptors: OriginalFirstThunk, TimeDateStamp, ForwarderChain,
    // Name, FirstThunk.
    img.u32(0x2150, 0x20C0);
    img.u32(0x2150 + 12, 0x2130);
    img.u32(0x2150 + 16, 0x2080);
    img.u32(0x2164, 0x20E0);
    img.u32(0x2164 + 12, 0x2140);
    img.u32(0x2164 + 16, 0x20A0);

    // Export directory.
    img.u32(0x21A0 + 12, 0x21E8); // Name
    img.u32(0x21A0 + 16, 1);      // Base
    img.u32(0x21A0 + 20, 2);      // NumberOfFunctions
    img.u32(0x21A0 + 24, 2);      // NumberOfNames
    img.u32(0x21A0 + 28, 0x21D0);
    img.u32(0x21A0 + 32, 0x21D8);
    img.u32(0x21A0 + 36, 0x21E0);
    img.u32(0x21D0, 0x1040);
    img.u32(0x21D4, 0x2220); // inside the directory, so a forwarder
    img.u32(0x21D8, 0x21F8);
    img.u32(0x21DC, 0x2208);
    img.u16(0x21E0, 0);
    img.u16(0x21E2, 1);
    img.str(0x21E8, "fixture.exe");
    img.str(0x21F8, "fixture_add");
    img.str(0x2208, "fixture_forward");
    img.str(0x2220, "KERNEL32.Sleep");

    // TLS directory and its callback list.
    img.ptr(0x2240, base + 0x3100, is64);
    img.ptr(0x2240 + ps, base + 0x3108, is64);
    img.ptr(0x2240 + 2 * ps, base + 0x3010, is64);
    img.ptr(0x2240 + 3 * ps, base + 0x2280, is64);
    img.ptr(0x2280, base + 0x1050, is64);

    // Debug directory with a CodeView (RSDS) record.
    img.u32(0x22A0 + 12, 2);
    img.u32(0x22A0 + 16, 24 + 12);
    img.u32(0x22A0 + 20, 0x22C0);
    img.u32(0x22A0 + 24, static_cast<std::uint32_t>(img.off(0x22C0)));
    img.u32(0x22C0, 0x53445352);
    for (std::uint8_t i = 0; i < 16; ++i) {
        img.file.at(img.off(0x22C4) + i) = static_cast<std::uint8_t>(0x10 + i);
    }
    img.u32(0x22D4, 1);
    img.str(0x22D8, "fixture.pdb");

    if (is64) {
        // Unwind info: main allocates 0x28 bytes of stack; fixture_add and
        // the TLS callback are leaves; the fragment at 0x1060 is chained to
        // fixture_add's entry.
        img.put(0x2300, {0x01, 0x04, 0x01, 0x00, 0x04, 0x42, 0x00, 0x00});
        img.put(0x2310, {0x01, 0x00, 0x00, 0x00});
        img.put(0x2320, {0x21, 0x00, 0x00, 0x00});
        img.u32(0x2324, 0x1040);
        img.u32(0x2328, 0x1044);
        img.u32(0x232C, 0x2310);
        img.put(0x2330, {0x01, 0x00, 0x00, 0x00});
    }
}

void writeData(Image& img, bool is64, std::uint64_t base) {
    img.u32(0x3000, 42);
    img.ptr(0x3008, base + 0x1040, is64);
}

void writePdata(Image& img) {
    const std::uint32_t entries[4][3] = {
        {0x1000, 0x1026, 0x2300},
        {0x1040, 0x1044, 0x2310},
        {0x1050, 0x1051, 0x2330},
        {0x1060, 0x106C, 0x2320},
    };
    for (std::uint32_t i = 0; i < 4; ++i) {
        img.u32(0x4000 + i * 12, entries[i][0]);
        img.u32(0x4000 + i * 12 + 4, entries[i][1]);
        img.u32(0x4000 + i * 12 + 8, entries[i][2]);
    }
}

void writeResources(Image& img) {
    const std::uint32_t r = 0x5000;
    // Root: one named type, one id type.
    img.u16(r + 12, 1);
    img.u16(r + 14, 1);
    img.u32(r + 16, 0x80000000u | 0x80); // name "TEXTFILE"
    img.u32(r + 20, 0x80000000u | 0x20);
    img.u32(r + 24, 24); // MANIFEST
    img.u32(r + 28, 0x80000000u | 0x38);
    // TEXTFILE -> #101
    img.u16(r + 0x20 + 14, 1);
    img.u32(r + 0x30, 101);
    img.u32(r + 0x34, 0x80000000u | 0x50);
    // MANIFEST -> #1
    img.u16(r + 0x38 + 14, 1);
    img.u32(r + 0x48, 1);
    img.u32(r + 0x4C, 0x80000000u | 0x68);
    // Languages.
    img.u16(r + 0x50 + 14, 1);
    img.u32(r + 0x60, 1033);
    img.u32(r + 0x64, 0xA0);
    img.u16(r + 0x68 + 14, 1);
    img.u32(r + 0x78, 1033);
    img.u32(r + 0x7C, 0xB0);
    // The type name, as a counted UTF-16 string.
    img.u16(r + 0x80, 8);
    std::size_t o = img.off(r + 0x82);
    for (char c : std::string_view("TEXTFILE")) {
        img.file.at(o++) = static_cast<std::uint8_t>(c);
        img.file.at(o++) = 0;
    }
    // Data entries and the data.
    const std::string_view text = "hello rsrc!\n";
    const std::string_view manifest = "<assembly manifestVersion='1.0'/>";
    img.u32(r + 0xA0, r + 0xC0);
    img.u32(r + 0xA4, static_cast<std::uint32_t>(text.size()));
    img.u32(r + 0xB0, r + 0xD0);
    img.u32(r + 0xB4, static_cast<std::uint32_t>(manifest.size()));
    img.str(r + 0xC0, text);
    img.str(r + 0xD0, manifest);
}

} // namespace

std::vector<std::uint8_t> build(bool is64) {
    const std::uint64_t base = is64 ? 0x140000000ull : 0x400000ull;
    Image img;
    img.sections.push_back({".text", 0x1000, 0x100, 0x400, 0x200, codeFlags});
    img.sections.push_back({".rdata", 0x2000, 0x400, 0x600, 0x400, rdataFlags});
    img.sections.push_back({".data", 0x3000, 0x1000, 0xA00, 0x200, dataFlags});
    std::uint32_t raw = 0xC00;
    if (is64) {
        img.sections.push_back({".pdata", 0x4000, 0x30, raw, 0x200, rdataFlags});
        raw += 0x200;
    }
    img.sections.push_back({".rsrc", 0x5000, 0x100, raw, 0x200, rdataFlags});
    raw += 0x200;
    img.file.assign(raw, 0);

    writeHeaders(img, is64, base);
    std::fill(img.file.begin() + img.off(0x1000), img.file.begin() + img.off(0x1000) + 0x200, std::uint8_t{0xCC});
    if (is64) {
        writeCode64(img);
    } else {
        writeCode32(img);
    }
    writeRdata(img, is64, base);
    writeData(img, is64, base);
    if (is64) {
        writePdata(img);
    }
    writeResources(img);

    dir(img, is64, 0, 0x21A0, 0x90);
    dir(img, is64, 1, 0x2150, 60);
    dir(img, is64, 2, 0x5000, 0x100);
    if (is64) {
        dir(img, is64, 3, 0x4000, 48);
    }
    dir(img, is64, 6, 0x22A0, 28);
    dir(img, is64, 9, 0x2240, is64 ? 40 : 24);
    dir(img, is64, 12, 0x2080, 0x28);

    const std::string_view overlay = "OVERLAY-DATA-END";
    img.file.insert(img.file.end(), overlay.begin(), overlay.end());
    return std::move(img.file);
}

std::vector<std::uint8_t> buildManyStrings(std::size_t count) {
    // A PE32+ whose .rdata is `count` strings of 24 characters each.
    const std::uint32_t perString = 32;
    std::uint32_t rawSize = static_cast<std::uint32_t>(count) * perString;
    rawSize = (rawSize + 0x1FF) & ~0x1FFu;
    Image img;
    img.sections.push_back({".text", 0x1000, 0x10, 0x400, 0x200, codeFlags});
    img.sections.push_back({".rdata", 0x2000, rawSize, 0x600, rawSize, rdataFlags});
    img.file.assign(0x600 + rawSize, 0);
    writeHeaders(img, true, 0x140000000ull);
    img.put(0x1000, {0xC3});
    for (std::size_t i = 0; i < count; ++i) {
        char text[32];
        std::snprintf(text, sizeof(text), "paging test string %05zu", i);
        img.str(0x2000 + static_cast<std::uint32_t>(i) * perString, text);
    }
    return std::move(img.file);
}

TempFile::TempFile(const std::vector<std::uint8_t>& bytes, const std::string& stem) {
    static std::atomic<unsigned> counter{0};
    path_ = std::filesystem::temp_directory_path() /
            (stem + "-" + std::to_string(::GetCurrentProcessId()) + "-" + std::to_string(counter++) + ".bin");
    std::ofstream out(path_, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

TempFile::~TempFile() {
    std::error_code ec;
    std::filesystem::remove(path_, ec);
}

std::string TempFile::utf8() const {
    const auto s = path_.u8string();
    return std::string(reinterpret_cast<const char*>(s.data()), s.size());
}

} // namespace synthetic
