#pragma once

// Zydis behind a small interface: decode one instruction, format it, and
// report every address it refers to.

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace pemcp {

class PeFile;

enum class RefKind { Call, Jmp, Jcc, Rip, Abs, Ptr };
[[nodiscard]] const char* refKindName(RefKind kind);

struct Reference {
    RefKind kind = RefKind::Abs;
    std::uint64_t va = 0;
};

struct Instruction {
    bool valid = false;
    std::uint8_t length = 1; // 1 for bytes that do not decode, so a sweep moves on
    std::string text;        // empty unless formatting was asked for
    std::vector<Reference> refs;
};

class Disassembler {
public:
    explicit Disassembler(bool is64);
    ~Disassembler();
    Disassembler(const Disassembler&) = delete;
    Disassembler& operator=(const Disassembler&) = delete;

    // Decodes the instruction at the front of `bytes`, which lives at `va`.
    // `format` controls whether `text` is filled in; a sweep that only needs
    // references skips it, which is most of the cost.
    [[nodiscard]] Instruction decode(std::span<const std::uint8_t> bytes, std::uint64_t va, bool format) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// One place an instruction (or, with includeData, a pointer in data) refers
// to the target range.
struct Xref {
    std::uint32_t rva = 0; // of the referring instruction or pointer
    RefKind kind = RefKind::Abs;
    std::string text; // the instruction, formatted
};

struct XrefQuery {
    std::uint32_t targetRva = 0;
    std::uint32_t size = 1; // references anywhere in [targetRva, targetRva + size) count
    bool includeData = false;
    std::size_t maxResults = 100000;
};

// Linear-sweep every executable section and collect the instructions that
// refer to the target: relative calls and jumps, RIP-relative operands and
// absolute addresses in immediates or displacements. With includeData,
// pointer-aligned absolute pointers in the other sections count too.
[[nodiscard]] std::vector<Xref> findXrefs(const PeFile& pe, const XrefQuery& query);

} // namespace pemcp
