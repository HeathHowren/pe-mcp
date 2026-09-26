#pragma once

// A read-only view of a PE32 or PE32+ file on disk.
//
// parse() checks the headers and builds the section table. Everything past the
// headers (imports, exports, TLS, resources, .pdata) is read on demand, and
// each of those readers returns what it could read plus warnings for what it
// could not, rather than failing the whole file. A half-broken import table
// still has useful entries in it, and an agent is better served by those and
// a sentence about the rest than by a refusal.

#include "pe/Bytes.h"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace pemcp {

enum class Arch { X86, X64, Other };

struct Section {
    std::string name;
    std::uint32_t rva = 0;
    std::uint32_t virtualSize = 0;
    std::uint32_t rawOffset = 0;
    std::uint32_t rawSize = 0; // clipped to the end of the file
    std::uint32_t characteristics = 0;

    [[nodiscard]] bool executable() const { return (characteristics & 0x20000000u) != 0 || (characteristics & 0x20u) != 0; }
    [[nodiscard]] bool readable() const { return (characteristics & 0x40000000u) != 0; }
    [[nodiscard]] bool writable() const { return (characteristics & 0x80000000u) != 0; }
    // The span of RVAs the loader maps for this section.
    [[nodiscard]] std::uint32_t mappedSize() const { return virtualSize > rawSize ? virtualSize : rawSize; }
};

struct DataDirectory {
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
};

// Directory indices, as in the PE specification.
enum DirIndex : std::size_t {
    DirExport = 0,
    DirImport = 1,
    DirResource = 2,
    DirException = 3,
    DirSecurity = 4,
    DirReloc = 5,
    DirDebug = 6,
    DirTls = 9,
    DirLoadConfig = 10,
    DirIat = 12,
    DirDelayImport = 13,
    DirClr = 14,
};

[[nodiscard]] const char* directoryName(std::size_t index);

struct Import {
    std::string dll;
    std::string name;          // empty for an import by ordinal
    std::uint16_t ordinal = 0; // set for an import by ordinal
    bool byOrdinal = false;
    std::uint32_t iatRva = 0; // the slot the loader fills, which code calls through
    bool delay = false;
};

struct ImportTable {
    std::vector<Import> imports; // in table order
    std::vector<std::string> warnings;
};

struct Export {
    std::uint32_t ordinal = 0;
    std::string name; // empty for an export by ordinal only
    std::uint32_t rva = 0;
    std::string forwarder; // "KERNEL32.Sleep" when forwarded
};

struct ExportTable {
    bool present = false;
    std::string dllName;
    std::uint32_t ordinalBase = 0;
    std::vector<Export> exports;
    std::vector<std::string> warnings;
};

struct TlsInfo {
    bool present = false;
    std::uint64_t rawDataStart = 0; // VAs, as stored
    std::uint64_t rawDataEnd = 0;
    std::uint64_t indexVa = 0;
    std::vector<std::uint64_t> callbacks; // VAs, as stored
    std::vector<std::string> warnings;
};

struct Resource {
    std::string type; // "ICON", "#300", or a string name
    std::string name; // "#1" or a string name
    std::uint32_t lang = 0;
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
    std::uint32_t codepage = 0;
};

struct ResourceTable {
    std::vector<Resource> resources;
    std::vector<std::string> warnings;
};

struct CodeView {
    std::string pdbPath;
    std::string guid;
    std::uint32_t age = 0;
};

struct FunctionRange {
    std::uint32_t begin = 0;
    std::uint32_t end = 0;
};

class PeFile {
public:
    // Parses the headers. On failure returns nothing and sets `error` to a
    // sentence saying what is wrong and where.
    [[nodiscard]] static std::optional<PeFile> parse(std::vector<std::uint8_t> bytes, std::string& error);
    [[nodiscard]] static std::optional<PeFile> load(const std::filesystem::path& path, std::string& error);

    // Files are read whole into memory, so there is a ceiling.
    static constexpr std::uint64_t maxFileSize = 1ull << 30;
    static constexpr std::size_t maxSections = 96; // the Windows loader's own limit

    [[nodiscard]] const std::vector<std::uint8_t>& bytes() const { return bytes_; }
    [[nodiscard]] ByteView view() const { return ByteView(bytes_); }

    [[nodiscard]] bool is64() const { return is64_; }
    [[nodiscard]] Arch arch() const;
    [[nodiscard]] std::uint16_t machine() const { return machine_; }
    [[nodiscard]] const char* machineName() const;
    [[nodiscard]] std::uint32_t pointerSize() const { return is64_ ? 8u : 4u; }
    [[nodiscard]] std::uint64_t imageBase() const { return imageBase_; }
    [[nodiscard]] std::uint32_t entryPoint() const { return entryPoint_; }
    [[nodiscard]] std::uint32_t sizeOfImage() const { return sizeOfImage_; }
    [[nodiscard]] std::uint32_t sizeOfHeaders() const { return sizeOfHeaders_; }
    [[nodiscard]] std::uint32_t ntOffset() const { return ntOffset_; }
    [[nodiscard]] std::uint32_t optionalHeaderOffset() const { return ntOffset_ + 24; }
    [[nodiscard]] const std::vector<Section>& sections() const { return sections_; }
    [[nodiscard]] const std::vector<DataDirectory>& directories() const { return directories_; }
    [[nodiscard]] DataDirectory directory(std::size_t index) const;
    [[nodiscard]] const std::vector<std::string>& headerWarnings() const { return warnings_; }

    // RVA <-> file offset. rvaToOffset answers only for bytes that are backed
    // by the file: the headers, or a section's raw data. An RVA in a section's
    // zero-filled tail has no file offset.
    [[nodiscard]] std::optional<std::uint64_t> rvaToOffset(std::uint64_t rva) const;
    [[nodiscard]] std::optional<std::uint32_t> offsetToRva(std::uint64_t offset) const;
    [[nodiscard]] const Section* sectionForRva(std::uint64_t rva) const;
    [[nodiscard]] const Section* sectionForOffset(std::uint64_t offset) const;
    [[nodiscard]] const Section* sectionByName(std::string_view name) const;
    [[nodiscard]] std::optional<std::uint32_t> vaToRva(std::uint64_t va) const;

    // Up to `length` file-backed bytes starting at `rva`. Stops early at the
    // end of the section's raw data, so the result may be shorter.
    [[nodiscard]] std::span<const std::uint8_t> readRva(std::uint64_t rva, std::uint64_t length) const;
    template <typename T>
    [[nodiscard]] std::optional<T> readRvaAs(std::uint64_t rva) const {
        const auto off = rvaToOffset(rva);
        if (!off) {
            return std::nullopt;
        }
        // The value must be wholly inside one file-backed run.
        if (readRva(rva, sizeof(T)).size() != sizeof(T)) {
            return std::nullopt;
        }
        return view().read<T>(*off);
    }
    [[nodiscard]] std::optional<std::string> cstringAtRva(std::uint64_t rva, std::size_t maxLength) const;

    // Data that follows the last section's raw data, if any.
    [[nodiscard]] std::optional<std::pair<std::uint64_t, std::uint64_t>> overlay() const;

    [[nodiscard]] ImportTable imports() const;
    [[nodiscard]] ExportTable exports() const;
    [[nodiscard]] TlsInfo tls() const;
    [[nodiscard]] ResourceTable resources() const;
    [[nodiscard]] std::optional<CodeView> codeView() const;

    // The function containing `rva`, from the x64 exception directory
    // (.pdata), following chained unwind info back to the primary entry.
    // Nothing on x86, which has no such table.
    [[nodiscard]] std::optional<FunctionRange> functionContaining(std::uint32_t rva) const;

    // Raw header fields for the headers tool.
    struct HeaderFields {
        std::uint32_t timestamp = 0;
        std::uint16_t characteristics = 0;
        std::uint16_t subsystem = 0;
        std::uint16_t dllCharacteristics = 0;
        std::uint32_t checksum = 0;
        std::uint32_t sectionAlignment = 0;
        std::uint32_t fileAlignment = 0;
        std::uint8_t linkerMajor = 0;
        std::uint8_t linkerMinor = 0;
        std::uint16_t osMajor = 0;
        std::uint16_t osMinor = 0;
        std::uint16_t declaredSections = 0;
    };
    [[nodiscard]] const HeaderFields& fields() const { return fields_; }

private:
    PeFile() = default;

    std::vector<std::uint8_t> bytes_;
    bool is64_ = false;
    std::uint16_t machine_ = 0;
    std::uint64_t imageBase_ = 0;
    std::uint32_t entryPoint_ = 0;
    std::uint32_t sizeOfImage_ = 0;
    std::uint32_t sizeOfHeaders_ = 0;
    std::uint32_t ntOffset_ = 0;
    HeaderFields fields_;
    std::vector<Section> sections_;
    std::vector<DataDirectory> directories_;
    std::vector<std::string> warnings_;
};

// UTF-16LE code units to UTF-8, with U+FFFD for anything malformed.
[[nodiscard]] std::string utf16ToUtf8(std::span<const std::uint8_t> bytes);

} // namespace pemcp
