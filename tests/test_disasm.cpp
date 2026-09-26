#include "SyntheticPe.h"
#include "pe/Disasm.h"
#include "pe/PeFile.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>

using namespace pemcp;

namespace {

PeFile parsed(bool is64) {
    std::string error;
    auto pe = PeFile::parse(synthetic::build(is64), error);
    REQUIRE(pe);
    return std::move(*pe);
}

std::vector<std::uint32_t> rvasOf(const std::vector<Xref>& refs) {
    std::vector<std::uint32_t> out;
    for (const auto& r : refs) {
        out.push_back(r.rva);
    }
    return out;
}

} // namespace

TEST_CASE("Each reference kind is reported with its target", "[disasm]") {
    const Disassembler dis(true);
    const std::uint64_t va = 0x140001000;

    const std::uint8_t call[] = {0xE8, 0x10, 0x00, 0x00, 0x00};
    auto ins = dis.decode(call, va, true);
    REQUIRE(ins.valid);
    CHECK(ins.length == 5);
    CHECK(ins.text == "call 0x140001015");
    REQUIRE(ins.refs.size() == 1);
    CHECK(ins.refs[0].kind == RefKind::Call);
    CHECK(ins.refs[0].va == 0x140001015);

    const std::uint8_t jcc[] = {0x74, 0x02};
    ins = dis.decode(jcc, va, false);
    REQUIRE(ins.refs.size() == 1);
    CHECK(ins.refs[0].kind == RefKind::Jcc);
    CHECK(ins.refs[0].va == 0x140001004);
    CHECK(ins.text.empty()); // not formatted when not asked

    const std::uint8_t lea[] = {0x48, 0x8D, 0x0D, 0xF9, 0x0F, 0x00, 0x00};
    ins = dis.decode(lea, va, true);
    REQUIRE(ins.refs.size() == 1);
    CHECK(ins.refs[0].kind == RefKind::Rip);
    CHECK(ins.refs[0].va == 0x140002000);
    CHECK(ins.text == "lea rcx, [0x140002000]");

    const std::uint8_t movabs[] = {0x48, 0xB8, 0x00, 0x20, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00};
    ins = dis.decode(movabs, va, false);
    REQUIRE(ins.refs.size() == 1);
    CHECK(ins.refs[0].kind == RefKind::Abs);
    CHECK(ins.refs[0].va == 0x140002000);
}

TEST_CASE("x86 absolute operands are references", "[disasm]") {
    const Disassembler dis(false);
    const std::uint8_t push[] = {0x68, 0x00, 0x20, 0x40, 0x00};
    auto ins = dis.decode(push, 0x401000, true);
    REQUIRE(ins.refs.size() == 1);
    CHECK(ins.refs[0].kind == RefKind::Abs);
    CHECK(ins.refs[0].va == 0x402000);
    CHECK(ins.text == "push 0x402000");

    // A jump table: [index*4 + table], where the displacement is the table.
    const std::uint8_t table[] = {0xFF, 0x24, 0x85, 0x00, 0x30, 0x40, 0x00};
    ins = dis.decode(table, 0x401000, false);
    REQUIRE(ins.refs.size() == 1);
    CHECK(ins.refs[0].va == 0x403000);
}

TEST_CASE("Bytes that do not decode advance by one and say so", "[disasm]") {
    const Disassembler dis(true);
    const std::uint8_t bad[] = {0x0F, 0xFF};
    const auto ins = dis.decode(bad, 0x1000, true);
    CHECK_FALSE(ins.valid);
    CHECK(ins.length == 1);
    CHECK(ins.text == "(bad)");
    CHECK_FALSE(dis.decode({}, 0x1000, true).valid);
}

TEST_CASE("xrefs to the string in the synthetic PE32+", "[disasm]") {
    const PeFile pe = parsed(true);
    const auto refs = findXrefs(pe, {0x2000, 1, false, 1000});
    CHECK(rvasOf(refs) == std::vector<std::uint32_t>{0x1004, 0x1060});
    CHECK(refs[0].kind == RefKind::Rip);
    CHECK(refs[0].text == "lea rcx, [0x140002000]");
}

TEST_CASE("xrefs to a function: calls, jumps and data pointers", "[disasm]") {
    const PeFile pe = parsed(true);
    auto refs = findXrefs(pe, {0x1040, 1, false, 1000});
    REQUIRE(refs.size() == 2);
    CHECK(refs[0].rva == 0x1016);
    CHECK(refs[0].kind == RefKind::Call);
    CHECK(refs[1].rva == 0x1067);
    CHECK(refs[1].kind == RefKind::Jmp);

    refs = findXrefs(pe, {0x1040, 1, true, 1000});
    REQUIRE(refs.size() == 3);
    CHECK(refs[2].rva == 0x3008);
    CHECK(refs[2].kind == RefKind::Ptr);
    CHECK(refs[2].text == "dq 0x140001040");
}

TEST_CASE("xrefs through an IAT slot and into a range", "[disasm]") {
    const PeFile pe = parsed(true);
    auto refs = findXrefs(pe, {0x2080, 1, false, 1000});
    REQUIRE(refs.size() == 1);
    CHECK(refs[0].rva == 0x100B);
    CHECK(refs[0].text == "call [0x140002080]");

    // A range covering the string and the IAT finds all three.
    refs = findXrefs(pe, {0x2000, 0x90, false, 1000});
    CHECK(rvasOf(refs) == std::vector<std::uint32_t>{0x1004, 0x100B, 0x1060});

    // maxResults stops the sweep.
    CHECK(findXrefs(pe, {0x2000, 0x90, false, 2}).size() == 2);
}

TEST_CASE("xrefs in the synthetic PE32 use absolute addresses", "[disasm]") {
    const PeFile pe = parsed(false);
    auto refs = findXrefs(pe, {0x2000, 1, false, 1000});
    CHECK(rvasOf(refs) == std::vector<std::uint32_t>{0x1003, 0x1060});
    CHECK(refs[0].kind == RefKind::Abs);
    refs = findXrefs(pe, {0x3000, 1, false, 1000});
    REQUIRE(refs.size() == 1);
    CHECK(refs[0].text == "mov eax, [0x403000]");
}
