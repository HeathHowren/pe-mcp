#include "pe/Disasm.h"

#include "pe/Bytes.h"
#include "pe/PeFile.h"

#include <Zydis/Zydis.h>

#include <algorithm>

namespace pemcp {

const char* refKindName(RefKind kind) {
    switch (kind) {
    case RefKind::Call:
        return "call";
    case RefKind::Jmp:
        return "jmp";
    case RefKind::Jcc:
        return "jcc";
    case RefKind::Rip:
        return "rip";
    case RefKind::Abs:
        return "abs";
    case RefKind::Ptr:
        return "ptr";
    }
    return "unknown";
}

struct Disassembler::Impl {
    ZydisDecoder decoder{};
    ZydisFormatter formatter{};
    bool is64 = true;
};

Disassembler::Disassembler(bool is64) : impl_(std::make_unique<Impl>()) {
    impl_->is64 = is64;
    if (is64) {
        ZydisDecoderInit(&impl_->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    } else {
        ZydisDecoderInit(&impl_->decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
    }
    ZydisFormatterInit(&impl_->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    // "0x140002000", not "0x0000000140002000": every byte of output lands in
    // a model's context.
    ZydisFormatterSetProperty(&impl_->formatter, ZYDIS_FORMATTER_PROP_ADDR_PADDING_ABSOLUTE, ZYDIS_PADDING_DISABLED);
    ZydisFormatterSetProperty(&impl_->formatter, ZYDIS_FORMATTER_PROP_ADDR_PADDING_RELATIVE, ZYDIS_PADDING_DISABLED);
}

Disassembler::~Disassembler() = default;

Instruction Disassembler::decode(std::span<const std::uint8_t> bytes, std::uint64_t va, bool format) const {
    Instruction out;
    ZydisDecodedInstruction instr;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    if (bytes.empty() || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&impl_->decoder, bytes.data(), bytes.size(), &instr, operands))) {
        if (format) {
            out.text = "(bad)";
        }
        return out;
    }
    out.valid = true;
    out.length = instr.length;
    const std::uint64_t widthMask = impl_->is64 ? ~0ull : 0xFFFFFFFFull;

    for (std::uint8_t i = 0; i < instr.operand_count_visible; ++i) {
        const ZydisDecodedOperand& op = operands[i];
        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            if (op.imm.is_relative) {
                ZyanU64 target = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr, &op, va, &target))) {
                    RefKind kind = RefKind::Jcc;
                    if (instr.meta.category == ZYDIS_CATEGORY_CALL) {
                        kind = RefKind::Call;
                    } else if (instr.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
                        kind = RefKind::Jmp;
                    }
                    out.refs.push_back({kind, target});
                }
            } else {
                out.refs.push_back({RefKind::Abs, op.imm.value.u & widthMask});
            }
        } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.type != ZYDIS_MEMOP_TYPE_MIB) {
            if (op.mem.base == ZYDIS_REGISTER_RIP || op.mem.base == ZYDIS_REGISTER_EIP) {
                ZyanU64 target = 0;
                if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instr, &op, va, &target))) {
                    out.refs.push_back({RefKind::Rip, target});
                }
            } else if (op.mem.base == ZYDIS_REGISTER_NONE && op.mem.disp.has_displacement) {
                // [disp] or [index*scale+disp]: the displacement is an address,
                // a global or the base of a jump table.
                out.refs.push_back({RefKind::Abs, static_cast<std::uint64_t>(op.mem.disp.value) & widthMask});
            }
        }
    }

    if (format) {
        char text[256];
        if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&impl_->formatter, &instr, operands, instr.operand_count_visible, text,
                                                         sizeof(text), va, ZYAN_NULL))) {
            out.text = text;
        } else {
            out.text = "(unformattable)";
        }
    }
    return out;
}

std::vector<Xref> findXrefs(const PeFile& pe, const XrefQuery& query) {
    std::vector<Xref> out;
    const Disassembler dis(pe.is64());
    const std::uint64_t lo = pe.imageBase() + query.targetRva;
    const std::uint64_t hi = lo + std::max<std::uint32_t>(query.size, 1);
    auto hits = [&](std::uint64_t va) { return va >= lo && va < hi; };

    for (const Section& s : pe.sections()) {
        if (out.size() >= query.maxResults) {
            break;
        }
        const auto bytes = pe.view().slice(s.rawOffset, s.rawSize);
        if (s.executable()) {
            std::size_t pos = 0;
            while (pos < bytes.size() && out.size() < query.maxResults) {
                const std::uint64_t rva = std::uint64_t{s.rva} + pos;
                const std::uint64_t va = pe.imageBase() + rva;
                const Instruction ins = dis.decode(bytes.subspan(pos), va, false);
                for (const Reference& r : ins.refs) {
                    if (hits(r.va)) {
                        const Instruction shown = dis.decode(bytes.subspan(pos), va, true);
                        out.push_back({static_cast<std::uint32_t>(rva), r.kind, shown.text});
                        break;
                    }
                }
                pos += ins.length;
            }
        } else if (query.includeData) {
            const std::uint32_t ps = pe.pointerSize();
            const ByteView v(bytes);
            // Pointers are aligned in the image, not necessarily in the file,
            // so the walk starts at the first aligned RVA.
            std::size_t pos = (ps - (s.rva % ps)) % ps;
            for (; pos + ps <= bytes.size() && out.size() < query.maxResults; pos += ps) {
                const std::uint64_t value = ps == 8 ? *v.read<std::uint64_t>(pos) : *v.read<std::uint32_t>(pos);
                if (hits(value)) {
                    out.push_back({static_cast<std::uint32_t>(s.rva + pos), RefKind::Ptr, (ps == 8 ? "dq " : "dd ") + hex(value)});
                }
            }
        }
    }
    std::stable_sort(out.begin(), out.end(), [](const Xref& a, const Xref& b) { return a.rva < b.rva; });
    return out;
}

} // namespace pemcp
