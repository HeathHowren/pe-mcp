#include "SyntheticPe.h"
#include "pe/PeFile.h"

#include <catch2/catch_test_macros.hpp>

using namespace pemcp;

namespace {

PeFile parsed(bool is64) {
    std::string error;
    auto pe = PeFile::parse(synthetic::build(is64), error);
    INFO(error);
    REQUIRE(pe);
    return std::move(*pe);
}

} // namespace

TEST_CASE("Headers of the synthetic PE32+ and PE32", "[pe]") {
    const PeFile pe64 = parsed(true);
    CHECK(pe64.is64());
    CHECK(pe64.arch() == Arch::X64);
    CHECK(pe64.imageBase() == 0x140000000ull);
    CHECK(pe64.entryPoint() == 0x1000);
    CHECK(pe64.sections().size() == 5);
    CHECK(pe64.headerWarnings().empty());

    const PeFile pe32 = parsed(false);
    CHECK_FALSE(pe32.is64());
    CHECK(pe32.arch() == Arch::X86);
    CHECK(pe32.imageBase() == 0x400000);
    CHECK(pe32.sections().size() == 4);
    CHECK(pe32.pointerSize() == 4);
}

TEST_CASE("RVA and file offset convert both ways", "[pe]") {
    const PeFile pe = parsed(true);
    CHECK(pe.rvaToOffset(0x1004) == 0x404u);
    CHECK(pe.rvaToOffset(0x2000) == 0x600u);
    CHECK(pe.rvaToOffset(0x10) == 0x10u); // headers map one to one
    CHECK(pe.offsetToRva(0x404) == 0x1004u);
    CHECK(pe.offsetToRva(0x10) == 0x10u);
    // .data is 0x1000 bytes in memory but 0x200 in the file.
    CHECK(pe.sectionForRva(0x3800) != nullptr);
    CHECK_FALSE(pe.rvaToOffset(0x3800));
    CHECK_FALSE(pe.rvaToOffset(0x9000));
    // The overlay is in the file but not in the image.
    const auto overlay = pe.overlay();
    REQUIRE(overlay);
    CHECK(overlay->second == 16);
    CHECK_FALSE(pe.offsetToRva(overlay->first));
    CHECK(pe.vaToRva(0x140001040ull) == 0x1040u);
    CHECK_FALSE(pe.vaToRva(0x1000));
}

TEST_CASE("readRva stops at the end of a section's file data", "[pe]") {
    const PeFile pe = parsed(true);
    CHECK(pe.readRva(0x31F0, 64).size() == 16);
    CHECK(pe.readRva(0x3200, 4).empty());
}

TEST_CASE("Imports, with IAT slots and ordinals", "[pe]") {
    for (bool is64 : {true, false}) {
        const PeFile pe = parsed(is64);
        const auto table = pe.imports();
        CHECK(table.warnings.empty());
        REQUIRE(table.imports.size() == 3);
        CHECK(table.imports[0].dll == "KERNEL32.dll");
        CHECK(table.imports[0].name == "OutputDebugStringA");
        CHECK(table.imports[0].iatRva == 0x2080);
        CHECK(table.imports[1].name == "GetTickCount");
        CHECK(table.imports[1].iatRva == (is64 ? 0x2088u : 0x2084u));
        CHECK(table.imports[2].dll == "USER32.dll");
        CHECK(table.imports[2].byOrdinal);
        CHECK(table.imports[2].ordinal == 7);
    }
}

TEST_CASE("Exports, including a forwarder", "[pe]") {
    const PeFile pe = parsed(true);
    const auto table = pe.exports();
    REQUIRE(table.present);
    CHECK(table.dllName == "fixture.exe");
    REQUIRE(table.exports.size() == 2);
    CHECK(table.exports[0].name == "fixture_add");
    CHECK(table.exports[0].rva == 0x1040);
    CHECK(table.exports[0].forwarder.empty());
    CHECK(table.exports[1].name == "fixture_forward");
    CHECK(table.exports[1].forwarder == "KERNEL32.Sleep");
    CHECK(table.exports[1].ordinal == 2);
}

TEST_CASE("TLS callbacks", "[pe]") {
    for (bool is64 : {true, false}) {
        const PeFile pe = parsed(is64);
        const auto tls = pe.tls();
        REQUIRE(tls.present);
        REQUIRE(tls.callbacks.size() == 1);
        CHECK(tls.callbacks[0] == pe.imageBase() + 0x1050);
    }
}

TEST_CASE("Resources as type, name and language", "[pe]") {
    const PeFile pe = parsed(true);
    const auto table = pe.resources();
    CHECK(table.warnings.empty());
    REQUIRE(table.resources.size() == 2);
    CHECK(table.resources[0].type == "TEXTFILE");
    CHECK(table.resources[0].name == "#101");
    CHECK(table.resources[0].lang == 1033);
    CHECK(table.resources[0].rva == 0x50C0);
    CHECK(table.resources[0].size == 12);
    CHECK(table.resources[1].type == "MANIFEST");
    CHECK(table.resources[1].name == "#1");
}

TEST_CASE("The CodeView record names the PDB", "[pe]") {
    const PeFile pe = parsed(true);
    const auto cv = pe.codeView();
    REQUIRE(cv);
    CHECK(cv->pdbPath == "fixture.pdb");
    CHECK(cv->age == 1);
    CHECK(cv->guid == "13121110-1514-1716-1819-1A1B1C1D1E1F");
}

TEST_CASE(".pdata finds the containing function and follows chained unwind info", "[pe]") {
    const PeFile pe = parsed(true);
    auto fn = pe.functionContaining(0x1004);
    REQUIRE(fn);
    CHECK(fn->begin == 0x1000);
    CHECK(fn->end == 0x1026);
    // 0x1060 is a fragment whose unwind info chains to fixture_add.
    fn = pe.functionContaining(0x1067);
    REQUIRE(fn);
    CHECK(fn->begin == 0x1040);
    CHECK(fn->end == 0x1044);
    CHECK_FALSE(pe.functionContaining(0x1030)); // padding between functions
    CHECK_FALSE(pe.functionContaining(0x0FFF));
    CHECK_FALSE(parsed(false).functionContaining(0x1004)); // x86 has no .pdata
}

TEST_CASE("UTF-16 conversion handles surrogates and malformed input", "[pe]") {
    const std::uint8_t pair[] = {0x3D, 0xD8, 0x00, 0xDE}; // U+1F600
    CHECK(utf16ToUtf8(pair) == "\xF0\x9F\x98\x80");
    const std::uint8_t lone[] = {0x00, 0xD8, 0x41, 0x00}; // a lone high surrogate, then 'A'
    CHECK(utf16ToUtf8(lone) == "\xEF\xBF\xBD" "A");
    const std::uint8_t odd[] = {0x41, 0x00, 0x42}; // a trailing odd byte is dropped
    CHECK(utf16ToUtf8(odd) == "A");
}
