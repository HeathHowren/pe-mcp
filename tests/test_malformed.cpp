// Malformed and truncated files: every tool must answer with JSON or a
// sentence, never crash, and never leak an internal exception.

#include "TestSupport.h"
#include "pe/PeFile.h"

#include <catch2/catch_test_macros.hpp>

#include <cstring>

using namespace testing;

namespace {

const char* const toolCalls[][2] = {
    {"headers", "{}"},
    {"sections", "{}"},
    {"imports", "{}"},
    {"exports", "{}"},
    {"strings", "{}"},
    {"disassemble", R"({"rva":"0x1000","count":50})"},
    {"disassemble", R"({"rva":"0x1004","function":true})"},
    {"xrefs_to", R"({"rva":"0x2000","include_data":true})"},
    {"xrefs_to", R"({"rva":"0x1040","size":4096})"},
    {"find_pattern", R"({"pattern":"E8 ?? ?? ?? ??"})"},
    {"read_bytes", R"({"rva":"0x1000","length":4096})"},
    {"read_bytes", R"({"offset":"0x0"})"},
    {"hash", "{}"},
    {"rva_to_offset", R"({"rva":"0x2000"})"},
    {"offset_to_rva", R"({"offset":"0x400"})"},
    {"tls_callbacks", "{}"},
    {"resources", "{}"},
};

// Opens the bytes and runs every tool. Returns false when the file was
// refused at open, which is a correct outcome for many mutations.
bool runAllTools(const std::vector<std::uint8_t>& bytes) {
    synthetic::TempFile file(bytes, "pemcp-fuzz");
    Session session;
    if (!session.openAtStartup(file.path()).empty()) {
        return false;
    }
    for (const auto& call : toolCalls) {
        const auto r = session.call(call[0], Json::parse(call[1]));
        INFO(call[0] << " " << call[1] << " -> " << r.text);
        REQUIRE_FALSE(r.text.empty());
        CHECK(r.text.rfind("Internal error", 0) == std::string::npos);
        CHECK(r.text.size() <= Session::maxResultBytes);
        if (r.ok) {
            CHECK_NOTHROW(Json::parse(r.text));
        }
    }
    return true;
}

std::string openError(const std::vector<std::uint8_t>& bytes) {
    std::string error;
    auto pe = pemcp::PeFile::parse(bytes, error);
    return pe ? std::string() : error;
}

void put32(std::vector<std::uint8_t>& b, std::size_t off, std::uint32_t v) {
    std::memcpy(&b.at(off), &v, 4);
}

void put16(std::vector<std::uint8_t>& b, std::size_t off, std::uint16_t v) {
    std::memcpy(&b.at(off), &v, 2);
}

// File offset of an RVA in .rdata, for both builds.
std::size_t rdata(std::uint32_t rva) {
    return synthetic::offsets::rdata + (rva - 0x2000);
}

// A small deterministic generator, so a failure reproduces.
struct XorShift {
    std::uint64_t s;
    std::uint64_t next() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }
};

} // namespace

TEST_CASE("Truncated files are refused or read in part, never crash", "[malformed]") {
    for (bool is64 : {true, false}) {
        const auto full = synthetic::build(is64);
        std::size_t opened = 0;
        for (std::size_t len = 0; len < full.size(); len += (len < 0x400 ? 3 : 29)) {
            INFO((is64 ? "x64" : "x86") << " truncated to " << len << " bytes");
            const std::vector<std::uint8_t> cut(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(len));
            if (runAllTools(cut)) {
                ++opened;
            }
        }
        // Once the headers and section table are in, the file opens and the
        // tools report what is missing.
        CHECK(opened > 20);
    }
}

TEST_CASE("Random mutations never crash a tool", "[malformed]") {
    XorShift rng{0x9E3779B97F4A7C15ull};
    for (bool is64 : {true, false}) {
        const auto base = synthetic::build(is64);
        for (int round = 0; round < 150; ++round) {
            auto bytes = base;
            const int edits = 1 + static_cast<int>(rng.next() % 8);
            for (int e = 0; e < edits; ++e) {
                const std::uint64_t r = rng.next();
                // Half the edits land in the headers, where one byte changes
                // the meaning of everything after it; the rest anywhere.
                const std::size_t at = (r & 1) ? (r >> 8) % 0x200 : (r >> 8) % bytes.size();
                if ((r >> 4) & 1) {
                    bytes[at] = static_cast<std::uint8_t>(rng.next());
                } else if (at + 4 <= bytes.size()) {
                    put32(bytes, at, static_cast<std::uint32_t>(rng.next()));
                }
            }
            INFO((is64 ? "x64" : "x86") << " round " << round);
            (void)runAllTools(bytes);
        }
    }
}

TEST_CASE("Header corruption is reported with a reason", "[malformed]") {
    auto b = synthetic::build(true);
    const std::size_t nt = synthetic::offsets::ntHeaders;

    auto noMz = b;
    noMz[0] = 'X';
    CHECK(openError(noMz) == "Not a PE file: it does not start with \"MZ\".");

    auto farNt = b;
    put32(farNt, 0x3C, 0xFFFFFFF0);
    CHECK(openError(farNt).find("the PE header offset 0xFFFFFFF0 (e_lfanew) is past the end") != std::string::npos);

    auto noPe = b;
    noPe[nt] = 'X';
    CHECK(openError(noPe) == "Not a PE file: there is no \"PE\" signature at 0x80.");

    auto rom = b;
    put16(rom, nt + 24, 0x107);
    CHECK(openError(rom).find("Unsupported optional header magic 0x107") == 0);

    auto tinyOpt = b;
    put16(tinyOpt, nt + 20, 16);
    CHECK(openError(tinyOpt).find("SizeOfOptionalHeader is 16") != std::string::npos);

    CHECK(openError({}).find("smaller than a DOS header") != std::string::npos);
}

TEST_CASE("Absurd counts are capped with a warning", "[malformed]") {
    auto b = synthetic::build(true);
    const std::size_t nt = synthetic::offsets::ntHeaders;

    SECTION("NumberOfSections") {
        put16(b, nt + 6, 0xFFFF);
        std::string error;
        const auto pe = pemcp::PeFile::parse(b, error);
        REQUIRE(pe);
        REQUIRE_FALSE(pe->headerWarnings().empty());
        CHECK(pe->headerWarnings()[0].find("only the first 96") != std::string::npos);
        CHECK(runAllTools(b));
    }
    SECTION("NumberOfRvaAndSizes") {
        put32(b, nt + 24 + 108, 0xFFFFFFFF);
        std::string error;
        const auto pe = pemcp::PeFile::parse(b, error);
        REQUIRE(pe);
        CHECK(pe->directories().size() == 16);
    }
    SECTION("Section data past the end of the file") {
        put32(b, synthetic::offsets::sectionTable64 + 40 + 20, 0x7FFFFFF0); // .rdata PointerToRawData
        std::string error;
        const auto pe = pemcp::PeFile::parse(b, error);
        REQUIRE(pe);
        CHECK(pe->headerWarnings()[0].find("past the end of the file") != std::string::npos);
        CHECK(pe->sections()[1].rawSize == 0);
        CHECK(runAllTools(b));
    }
    SECTION("Export NumberOfFunctions") {
        put32(b, rdata(0x21A0 + 20), 0xFFFFFFFF);
        std::string error;
        const auto pe = pemcp::PeFile::parse(b, error);
        REQUIRE(pe);
        const auto table = pe->exports();
        REQUIRE(table.warnings.size() >= 1);
        CHECK(table.warnings[0].find("only the first 65536") != std::string::npos);
        CHECK(runAllTools(b));
    }
}

TEST_CASE("Broken tables yield partial results and warnings", "[malformed]") {
    auto b = synthetic::build(true);

    SECTION("An import name outside the file") {
        put32(b, rdata(0x2150 + 12), 0xDEADBEEF);
        std::string error;
        const auto pe = pemcp::PeFile::parse(b, error);
        REQUIRE(pe);
        const auto table = pe->imports();
        CHECK(table.imports.size() == 3);
        CHECK(table.imports[0].dll == "?");
        REQUIRE_FALSE(table.warnings.empty());
        CHECK(table.warnings[0].find("0xDEADBEEF") != std::string::npos);
    }
    SECTION("An import lookup table with no terminator") {
        // Point USER32's lookup table at the end of .rdata, where it runs
        // into the end of the section's file data.
        put32(b, rdata(0x2164), 0x23F8);
        put32(b, rdata(0x23F8), 0x2118);
        put32(b, rdata(0x23FC), 0x2118);
        std::string error;
        const auto pe = pemcp::PeFile::parse(b, error);
        REQUIRE(pe);
        const auto table = pe->imports();
        REQUIRE_FALSE(table.warnings.empty());
        CHECK(table.warnings.back().find("USER32.dll: the thunk at RVA 0x2400 is not in the file") == 0);
    }
    SECTION("A resource directory that loops back to the root") {
        put32(b, synthetic::offsets::rsrc64 + 0x34, 0x80000000u); // TEXTFILE/#101 -> root
        std::string error;
        const auto pe = pemcp::PeFile::parse(b, error);
        REQUIRE(pe);
        const auto table = pe->resources();
        REQUIRE_FALSE(table.warnings.empty());
        CHECK(table.warnings[0].find("loops back") != std::string::npos);
        CHECK(table.resources.size() == 1); // the MANIFEST branch is intact
    }
    SECTION("A TLS callback list with no terminator") {
        // Point AddressOfCallBacks at the last pointer of .rdata's file data.
        const std::uint64_t va = 0x140000000ull + 0x23F8;
        std::memcpy(&b.at(rdata(0x2240 + 24)), &va, 8);
        const std::uint64_t cb = 0x140001050ull;
        std::memcpy(&b.at(rdata(0x23F8)), &cb, 8);
        std::string error;
        const auto pe = pemcp::PeFile::parse(b, error);
        REQUIRE(pe);
        const auto tls = pe->tls();
        CHECK(tls.callbacks.size() == 1);
        REQUIRE_FALSE(tls.warnings.empty());
        CHECK(tls.warnings[0].find("before its terminator") != std::string::npos);
    }
    SECTION("A .pdata directory full of garbage") {
        for (std::size_t i = 0; i < 48; ++i) {
            b.at(0xC00 + i) = static_cast<std::uint8_t>(0xA5 ^ i);
        }
        CHECK(runAllTools(b));
    }
}
