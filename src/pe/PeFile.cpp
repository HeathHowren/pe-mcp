#include "pe/PeFile.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <set>

namespace pemcp {

namespace {

constexpr std::uint16_t machineI386 = 0x014C;
constexpr std::uint16_t machineAmd64 = 0x8664;

// Caps on how much of each table is read. They are far above anything a real
// linker writes, and exist so a corrupt count cannot turn one call into a
// minute of work or a gigabyte of JSON.
constexpr std::size_t maxImportDescriptors = 4096;
constexpr std::size_t maxThunksPerDll = 16384;
constexpr std::size_t maxImports = 100000;
constexpr std::uint32_t maxExportFunctions = 65536;
constexpr std::size_t maxTlsCallbacks = 256;
constexpr std::size_t maxResources = 20000;
constexpr std::size_t maxEntriesPerResourceDir = 4096;
constexpr std::size_t maxNameLength = 512;

std::string at(std::uint64_t value) {
    return hex(value);
}

} // namespace

const char* directoryName(std::size_t index) {
    static constexpr const char* names[16] = {
        "export", "import", "resource", "exception", "security",     "basereloc",    "debug", "architecture",
        "globalptr", "tls", "load_config", "bound_import", "iat", "delay_import", "clr",   "reserved",
    };
    return index < 16 ? names[index] : "unknown";
}

std::string utf16ToUtf8(std::span<const std::uint8_t> bytes) {
    std::string out;
    const std::size_t units = bytes.size() / 2;
    auto unit = [&](std::size_t i) { return static_cast<std::uint32_t>(bytes[2 * i] | (bytes[2 * i + 1] << 8)); };
    auto append = [&](std::uint32_t cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    };
    for (std::size_t i = 0; i < units; ++i) {
        const std::uint32_t u = unit(i);
        if (u >= 0xD800 && u <= 0xDBFF && i + 1 < units) {
            const std::uint32_t low = unit(i + 1);
            if (low >= 0xDC00 && low <= 0xDFFF) {
                append(0x10000 + ((u - 0xD800) << 10) + (low - 0xDC00));
                ++i;
                continue;
            }
        }
        if (u >= 0xD800 && u <= 0xDFFF) {
            append(0xFFFD);
        } else if (u < 0x20 && u != '\t') {
            append('?');
        } else {
            append(u);
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

std::optional<PeFile> PeFile::load(const std::filesystem::path& path, std::string& error) {
    std::error_code ec;
    if (std::filesystem::is_directory(path, ec)) {
        error = "That is a directory, not a file.";
        return std::nullopt;
    }
    const auto size = std::filesystem::file_size(path, ec);
    if (ec) {
        error = "Cannot open the file: " + ec.message();
        return std::nullopt;
    }
    if (size > maxFileSize) {
        error = "The file is " + std::to_string(size) + " bytes; pe-mcp reads files whole and stops at 1 GiB.";
        return std::nullopt;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "Cannot open the file for reading.";
        return std::nullopt;
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    if (size != 0 && !in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size))) {
        error = "Could not read the whole file.";
        return std::nullopt;
    }
    return parse(std::move(bytes), error);
}

std::optional<PeFile> PeFile::parse(std::vector<std::uint8_t> bytes, std::string& error) {
    PeFile pe;
    pe.bytes_ = std::move(bytes);
    const ByteView v = pe.view();

    if (v.size() < 0x40) {
        error = "Not a PE file: it is " + std::to_string(v.size()) + " bytes, smaller than a DOS header.";
        return std::nullopt;
    }
    if (v.read<std::uint16_t>(0) != std::uint16_t{0x5A4D}) {
        error = "Not a PE file: it does not start with \"MZ\".";
        return std::nullopt;
    }
    const std::uint32_t nt = *v.read<std::uint32_t>(0x3C);
    if (!v.contains(nt, 24)) {
        error = "The file is truncated or corrupt: the PE header offset " + at(nt) + " (e_lfanew) is past the end of the " +
                std::to_string(v.size()) + "-byte file.";
        return std::nullopt;
    }
    if (v.read<std::uint32_t>(nt) != std::uint32_t{0x00004550}) {
        error = "Not a PE file: there is no \"PE\" signature at " + at(nt) + ".";
        return std::nullopt;
    }
    pe.ntOffset_ = nt;
    pe.machine_ = *v.read<std::uint16_t>(nt + 4);
    pe.fields_.declaredSections = *v.read<std::uint16_t>(nt + 6);
    pe.fields_.timestamp = *v.read<std::uint32_t>(nt + 8);
    const std::uint16_t optSize = *v.read<std::uint16_t>(nt + 20);
    pe.fields_.characteristics = *v.read<std::uint16_t>(nt + 22);

    const std::uint64_t opt = std::uint64_t{nt} + 24;
    const auto magic = v.read<std::uint16_t>(opt);
    if (!magic) {
        error = "The file is truncated: it ends inside the COFF header.";
        return std::nullopt;
    }
    if (*magic == 0x10B) {
        pe.is64_ = false;
    } else if (*magic == 0x20B) {
        pe.is64_ = true;
    } else {
        error = "Unsupported optional header magic " + at(*magic) + "; pe-mcp reads PE32 (0x10B) and PE32+ (0x20B).";
        return std::nullopt;
    }
    const std::uint32_t fixed = pe.is64_ ? 112 : 96;
    if (optSize < fixed) {
        error = "Corrupt header: SizeOfOptionalHeader is " + std::to_string(optSize) + ", smaller than the " +
                std::to_string(fixed) + " bytes a " + (pe.is64_ ? "PE32+" : "PE32") + " optional header needs.";
        return std::nullopt;
    }
    if (!v.contains(opt, fixed)) {
        error = "The file is truncated: it ends inside the optional header.";
        return std::nullopt;
    }
    auto& f = pe.fields_;
    f.linkerMajor = *v.read<std::uint8_t>(opt + 2);
    f.linkerMinor = *v.read<std::uint8_t>(opt + 3);
    pe.entryPoint_ = *v.read<std::uint32_t>(opt + 16);
    pe.imageBase_ = pe.is64_ ? *v.read<std::uint64_t>(opt + 24) : *v.read<std::uint32_t>(opt + 28);
    f.sectionAlignment = *v.read<std::uint32_t>(opt + 32);
    f.fileAlignment = *v.read<std::uint32_t>(opt + 36);
    f.osMajor = *v.read<std::uint16_t>(opt + 40);
    f.osMinor = *v.read<std::uint16_t>(opt + 42);
    pe.sizeOfImage_ = *v.read<std::uint32_t>(opt + 56);
    pe.sizeOfHeaders_ = *v.read<std::uint32_t>(opt + 60);
    f.checksum = *v.read<std::uint32_t>(opt + 64);
    f.subsystem = *v.read<std::uint16_t>(opt + 68);
    f.dllCharacteristics = *v.read<std::uint16_t>(opt + 70);

    const std::uint32_t declaredDirs = *v.read<std::uint32_t>(opt + (pe.is64_ ? 108 : 92));
    std::uint32_t dirs = std::min<std::uint32_t>(declaredDirs, 16);
    dirs = std::min<std::uint32_t>(dirs, (optSize - fixed) / 8);
    if (dirs < std::min<std::uint32_t>(declaredDirs, 16)) {
        pe.warnings_.push_back("NumberOfRvaAndSizes is " + std::to_string(declaredDirs) + " but the optional header has room for " +
                               std::to_string(dirs) + " directories; the rest are ignored.");
    }
    for (std::uint32_t i = 0; i < dirs; ++i) {
        const std::uint64_t d = opt + fixed + std::uint64_t{i} * 8;
        const auto rva = v.read<std::uint32_t>(d);
        const auto size = v.read<std::uint32_t>(d + 4);
        if (!rva || !size) {
            pe.warnings_.push_back("The file ends inside the data directories; only " + std::to_string(i) + " were read.");
            break;
        }
        pe.directories_.push_back({*rva, *size});
    }

    const std::uint64_t table = opt + optSize;
    std::size_t count = f.declaredSections;
    if (count > maxSections) {
        pe.warnings_.push_back("NumberOfSections is " + std::to_string(count) + "; only the first " + std::to_string(maxSections) +
                               " are read, as the Windows loader does.");
        count = maxSections;
    }
    for (std::size_t i = 0; i < count; ++i) {
        const std::uint64_t s = table + i * 40;
        if (!v.contains(s, 40)) {
            pe.warnings_.push_back("The section table is truncated; " + std::to_string(i) + " of " + std::to_string(count) +
                                   " sections were read.");
            break;
        }
        Section sec;
        const auto nameBytes = v.slice(s, 8);
        std::string name(reinterpret_cast<const char*>(nameBytes.data()), nameBytes.size());
        name.resize(std::min(name.find('\0'), name.size()));
        sec.name = printable(name);
        sec.virtualSize = *v.read<std::uint32_t>(s + 8);
        sec.rva = *v.read<std::uint32_t>(s + 12);
        const std::uint32_t rawSize = *v.read<std::uint32_t>(s + 16);
        sec.rawOffset = *v.read<std::uint32_t>(s + 20);
        sec.characteristics = *v.read<std::uint32_t>(s + 36);
        if (rawSize != 0 && sec.rawOffset >= v.size()) {
            pe.warnings_.push_back("Section " + std::to_string(i) + " (" + sec.name + ") has raw data at " + at(sec.rawOffset) +
                                   ", past the end of the file.");
            sec.rawSize = 0;
        } else if (rawSize > v.size() - sec.rawOffset) {
            pe.warnings_.push_back("Section " + std::to_string(i) + " (" + sec.name + ") is cut short by the end of the file.");
            sec.rawSize = static_cast<std::uint32_t>(v.size() - sec.rawOffset);
        } else {
            sec.rawSize = rawSize;
        }
        pe.sections_.push_back(std::move(sec));
    }
    if (pe.sections_.empty()) {
        pe.warnings_.push_back("The file has no sections.");
    }
    return pe;
}

Arch PeFile::arch() const {
    if (machine_ == machineAmd64 && is64_) {
        return Arch::X64;
    }
    if (machine_ == machineI386 && !is64_) {
        return Arch::X86;
    }
    return Arch::Other;
}

const char* PeFile::machineName() const {
    switch (machine_) {
    case machineI386:
        return "x86";
    case machineAmd64:
        return "x64";
    case 0xAA64:
        return "arm64";
    case 0x01C4:
        return "arm";
    case 0x0200:
        return "ia64";
    default:
        return "unknown";
    }
}

DataDirectory PeFile::directory(std::size_t index) const {
    return index < directories_.size() ? directories_[index] : DataDirectory{};
}

// ---------------------------------------------------------------------------
// Address mapping
// ---------------------------------------------------------------------------

const Section* PeFile::sectionForRva(std::uint64_t rva) const {
    for (const auto& s : sections_) {
        if (rva >= s.rva && rva - s.rva < s.mappedSize()) {
            return &s;
        }
    }
    return nullptr;
}

const Section* PeFile::sectionForOffset(std::uint64_t offset) const {
    for (const auto& s : sections_) {
        if (offset >= s.rawOffset && offset - s.rawOffset < s.rawSize) {
            return &s;
        }
    }
    return nullptr;
}

const Section* PeFile::sectionByName(std::string_view name) const {
    for (const auto& s : sections_) {
        if (s.name == name) {
            return &s;
        }
    }
    return nullptr;
}

std::optional<std::uint64_t> PeFile::rvaToOffset(std::uint64_t rva) const {
    if (const Section* s = sectionForRva(rva)) {
        const std::uint64_t delta = rva - s->rva;
        if (delta < s->rawSize) {
            return std::uint64_t{s->rawOffset} + delta;
        }
        return std::nullopt;
    }
    if (rva < sizeOfHeaders_ && rva < bytes_.size()) {
        return rva;
    }
    return std::nullopt;
}

std::optional<std::uint32_t> PeFile::offsetToRva(std::uint64_t offset) const {
    if (const Section* s = sectionForOffset(offset)) {
        return static_cast<std::uint32_t>(s->rva + (offset - s->rawOffset));
    }
    if (offset < sizeOfHeaders_ && offset < bytes_.size()) {
        return static_cast<std::uint32_t>(offset);
    }
    return std::nullopt;
}

std::optional<std::uint32_t> PeFile::vaToRva(std::uint64_t va) const {
    if (va < imageBase_ || va - imageBase_ > 0xFFFFFFFFull) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(va - imageBase_);
}

std::span<const std::uint8_t> PeFile::readRva(std::uint64_t rva, std::uint64_t length) const {
    const auto off = rvaToOffset(rva);
    if (!off) {
        return {};
    }
    std::uint64_t runEnd = 0;
    if (const Section* s = sectionForRva(rva)) {
        runEnd = std::uint64_t{s->rawOffset} + s->rawSize;
    } else {
        runEnd = std::min<std::uint64_t>(sizeOfHeaders_, bytes_.size());
    }
    return view().slice(*off, std::min(length, runEnd - *off));
}

std::optional<std::string> PeFile::cstringAtRva(std::uint64_t rva, std::size_t maxLength) const {
    const auto bytes = readRva(rva, maxLength + 1);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (bytes[i] == 0) {
            return printable(std::string_view(reinterpret_cast<const char*>(bytes.data()), i));
        }
    }
    return std::nullopt;
}

std::optional<std::pair<std::uint64_t, std::uint64_t>> PeFile::overlay() const {
    std::uint64_t end = std::min<std::uint64_t>(sizeOfHeaders_, bytes_.size());
    bool any = false;
    for (const auto& s : sections_) {
        if (s.rawSize != 0) {
            end = std::max<std::uint64_t>(end, std::uint64_t{s.rawOffset} + s.rawSize);
            any = true;
        }
    }
    if (!any || end >= bytes_.size()) {
        return std::nullopt;
    }
    return std::make_pair(end, bytes_.size() - end);
}

// ---------------------------------------------------------------------------
// Imports
// ---------------------------------------------------------------------------

namespace {

// Reads one thunk array (the import lookup table or, for delay loads, the
// import name table) and appends one Import per entry.
void readThunks(const PeFile& pe, ImportTable& table, const std::string& dll, std::uint64_t thunkRva, std::uint64_t iatRva,
                bool delay) {
    const std::uint32_t ps = pe.pointerSize();
    const std::uint64_t ordinalFlag = pe.is64() ? (1ull << 63) : (1ull << 31);
    for (std::size_t j = 0; j < maxThunksPerDll; ++j) {
        if (table.imports.size() >= maxImports) {
            table.warnings.push_back("Stopped after " + std::to_string(maxImports) + " imports.");
            return;
        }
        const std::uint64_t at = thunkRva + j * ps;
        std::optional<std::uint64_t> value;
        if (pe.is64()) {
            value = pe.readRvaAs<std::uint64_t>(at);
        } else if (auto v32 = pe.readRvaAs<std::uint32_t>(at)) {
            value = *v32;
        }
        if (!value) {
            table.warnings.push_back(dll + ": the thunk at RVA " + hex(at) + " is not in the file; the list stops there.");
            return;
        }
        if (*value == 0) {
            return;
        }
        Import imp;
        imp.dll = dll;
        imp.iatRva = static_cast<std::uint32_t>(iatRva + j * ps);
        imp.delay = delay;
        if ((*value & ordinalFlag) != 0) {
            imp.byOrdinal = true;
            imp.ordinal = static_cast<std::uint16_t>(*value & 0xFFFF);
        } else {
            const std::uint64_t hintName = *value & 0x7FFFFFFFull;
            if (auto name = pe.cstringAtRva(hintName + 2, maxNameLength)) {
                imp.name = *name;
            } else {
                imp.name = "?";
                table.warnings.push_back(dll + ": the name at RVA " + hex(hintName) + " is not in the file.");
            }
        }
        table.imports.push_back(std::move(imp));
    }
    table.warnings.push_back(dll + ": stopped after " + std::to_string(maxThunksPerDll) + " entries.");
}

} // namespace

ImportTable PeFile::imports() const {
    ImportTable table;
    const DataDirectory dir = directory(DirImport);
    if (dir.rva != 0) {
        for (std::size_t i = 0;; ++i) {
            if (i >= maxImportDescriptors) {
                table.warnings.push_back("Stopped after " + std::to_string(maxImportDescriptors) + " import descriptors.");
                break;
            }
            const std::uint64_t d = std::uint64_t{dir.rva} + i * 20;
            const auto oft = readRvaAs<std::uint32_t>(d);
            const auto nameRva = readRvaAs<std::uint32_t>(d + 12);
            const auto ft = readRvaAs<std::uint32_t>(d + 16);
            if (!oft || !nameRva || !ft) {
                table.warnings.push_back("Import descriptor " + std::to_string(i) + " at RVA " + hex(d) +
                                         " is not in the file; the table stops there.");
                break;
            }
            if (*oft == 0 && *nameRva == 0 && *ft == 0) {
                break;
            }
            auto dll = cstringAtRva(*nameRva, 256);
            if (!dll) {
                table.warnings.push_back("Import descriptor " + std::to_string(i) + " has a name RVA " + hex(*nameRva) +
                                         " that is not in the file.");
                dll = "?";
            }
            readThunks(*this, table, *dll, *oft != 0 ? *oft : *ft, *ft, false);
        }
    }

    const DataDirectory delay = directory(DirDelayImport);
    if (delay.rva != 0) {
        for (std::size_t i = 0; i < maxImportDescriptors; ++i) {
            const std::uint64_t d = std::uint64_t{delay.rva} + i * 32;
            const auto attributes = readRvaAs<std::uint32_t>(d);
            const auto nameField = readRvaAs<std::uint32_t>(d + 4);
            const auto iatField = readRvaAs<std::uint32_t>(d + 12);
            const auto intField = readRvaAs<std::uint32_t>(d + 16);
            if (!attributes || !nameField || !iatField || !intField) {
                table.warnings.push_back("Delay-import descriptor " + std::to_string(i) + " is not in the file; the table stops there.");
                break;
            }
            if (*nameField == 0 && *iatField == 0 && *intField == 0) {
                break;
            }
            // Attribute bit 0 clear is the old Visual C++ 6 layout, whose
            // fields are VAs rather than RVAs.
            auto toRva = [&](std::uint32_t field) -> std::uint64_t {
                if ((*attributes & 1) != 0) {
                    return field;
                }
                return field >= imageBase_ ? field - imageBase_ : field;
            };
            auto dll = cstringAtRva(toRva(*nameField), 256);
            if (!dll) {
                table.warnings.push_back("Delay-import descriptor " + std::to_string(i) + " has a name that is not in the file.");
                dll = "?";
            }
            readThunks(*this, table, *dll, toRva(*intField), toRva(*iatField), true);
        }
    }
    return table;
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

ExportTable PeFile::exports() const {
    ExportTable table;
    const DataDirectory dir = directory(DirExport);
    if (dir.rva == 0) {
        return table;
    }
    const std::uint64_t d = dir.rva;
    const auto nameRva = readRvaAs<std::uint32_t>(d + 12);
    const auto base = readRvaAs<std::uint32_t>(d + 16);
    const auto nFunctions = readRvaAs<std::uint32_t>(d + 20);
    const auto nNames = readRvaAs<std::uint32_t>(d + 24);
    const auto functions = readRvaAs<std::uint32_t>(d + 28);
    const auto names = readRvaAs<std::uint32_t>(d + 32);
    const auto ordinals = readRvaAs<std::uint32_t>(d + 36);
    if (!nameRva || !base || !nFunctions || !nNames || !functions || !names || !ordinals) {
        table.warnings.push_back("The export directory at RVA " + hex(d) + " is not in the file.");
        return table;
    }
    table.present = true;
    table.dllName = cstringAtRva(*nameRva, 256).value_or("");
    table.ordinalBase = *base;

    std::uint32_t count = *nFunctions;
    if (count > maxExportFunctions) {
        table.warnings.push_back("NumberOfFunctions is " + std::to_string(count) + "; only the first " +
                                 std::to_string(maxExportFunctions) + " are read.");
        count = maxExportFunctions;
    }
    std::vector<std::string> nameOf(count);
    const std::uint32_t nameCount = std::min(*nNames, maxExportFunctions);
    for (std::uint32_t i = 0; i < nameCount; ++i) {
        const auto nr = readRvaAs<std::uint32_t>(std::uint64_t{*names} + 4ull * i);
        const auto ord = readRvaAs<std::uint16_t>(std::uint64_t{*ordinals} + 2ull * i);
        if (!nr || !ord) {
            table.warnings.push_back("The export name table is cut short after " + std::to_string(i) + " names.");
            break;
        }
        if (*ord < count && nameOf[*ord].empty()) {
            nameOf[*ord] = cstringAtRva(*nr, maxNameLength).value_or("?");
        }
    }
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto rva = readRvaAs<std::uint32_t>(std::uint64_t{*functions} + 4ull * i);
        if (!rva) {
            table.warnings.push_back("The export address table is cut short after " + std::to_string(i) + " entries.");
            break;
        }
        if (*rva == 0) {
            continue;
        }
        Export e;
        e.ordinal = *base + i;
        e.name = nameOf[i];
        e.rva = *rva;
        if (*rva >= dir.rva && *rva - dir.rva < dir.size) {
            e.forwarder = cstringAtRva(*rva, 256).value_or("?");
        }
        table.exports.push_back(std::move(e));
    }
    return table;
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

TlsInfo PeFile::tls() const {
    TlsInfo info;
    const DataDirectory dir = directory(DirTls);
    if (dir.rva == 0) {
        return info;
    }
    const std::uint32_t ps = pointerSize();
    auto readPtr = [&](std::uint64_t rva) -> std::optional<std::uint64_t> {
        if (is64_) {
            return readRvaAs<std::uint64_t>(rva);
        }
        if (auto v = readRvaAs<std::uint32_t>(rva)) {
            return *v;
        }
        return std::nullopt;
    };
    const auto start = readPtr(dir.rva);
    const auto end = readPtr(dir.rva + ps);
    const auto index = readPtr(dir.rva + 2ull * ps);
    const auto callbacks = readPtr(dir.rva + 3ull * ps);
    if (!start || !end || !index || !callbacks) {
        info.warnings.push_back("The TLS directory at RVA " + hex(dir.rva) + " is not in the file.");
        return info;
    }
    info.present = true;
    info.rawDataStart = *start;
    info.rawDataEnd = *end;
    info.indexVa = *index;
    if (*callbacks == 0) {
        return info;
    }
    const auto listRva = vaToRva(*callbacks);
    if (!listRva) {
        info.warnings.push_back("AddressOfCallBacks " + hex(*callbacks) + " is below the image base.");
        return info;
    }
    for (std::size_t i = 0;; ++i) {
        if (i >= maxTlsCallbacks) {
            info.warnings.push_back("Stopped after " + std::to_string(maxTlsCallbacks) + " callbacks.");
            break;
        }
        const auto cb = readPtr(*listRva + i * ps);
        if (!cb) {
            info.warnings.push_back("The callback list at RVA " + hex(*listRva) + " runs out of the file before its terminator.");
            break;
        }
        if (*cb == 0) {
            break;
        }
        info.callbacks.push_back(*cb);
    }
    return info;
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

namespace {

const char* resourceTypeName(std::uint32_t id) {
    switch (id) {
    case 1: return "CURSOR";
    case 2: return "BITMAP";
    case 3: return "ICON";
    case 4: return "MENU";
    case 5: return "DIALOG";
    case 6: return "STRING";
    case 7: return "FONTDIR";
    case 8: return "FONT";
    case 9: return "ACCELERATOR";
    case 10: return "RCDATA";
    case 11: return "MESSAGETABLE";
    case 12: return "GROUP_CURSOR";
    case 14: return "GROUP_ICON";
    case 16: return "VERSION";
    case 17: return "DLGINCLUDE";
    case 19: return "PLUGPLAY";
    case 20: return "VXD";
    case 21: return "ANICURSOR";
    case 22: return "ANIICON";
    case 23: return "HTML";
    case 24: return "MANIFEST";
    default: return nullptr;
    }
}

struct ResourceWalker {
    const PeFile& pe;
    std::uint64_t base;
    ResourceTable& table;
    std::set<std::uint64_t> visited;

    std::string label(std::uint32_t nameField, int level) {
        if ((nameField & 0x80000000u) != 0) {
            const std::uint64_t at = base + (nameField & 0x7FFFFFFFu);
            const auto length = pe.readRvaAs<std::uint16_t>(at);
            if (!length) {
                table.warnings.push_back("A resource name at RVA " + hex(at) + " is not in the file.");
                return "?";
            }
            const std::size_t units = std::min<std::size_t>(*length, 256);
            const auto chars = pe.readRva(at + 2, units * 2);
            return utf16ToUtf8(chars);
        }
        const std::uint32_t id = nameField & 0xFFFF;
        if (level == 0) {
            if (const char* known = resourceTypeName(id)) {
                return known;
            }
        }
        return "#" + std::to_string(id);
    }

    void walk(std::uint32_t dirOffset, int level, Resource path) {
        const std::uint64_t d = base + dirOffset;
        if (!visited.insert(d).second) {
            table.warnings.push_back("The resource tree loops back to RVA " + hex(d) + "; that branch is skipped.");
            return;
        }
        const auto named = pe.readRvaAs<std::uint16_t>(d + 12);
        const auto ids = pe.readRvaAs<std::uint16_t>(d + 14);
        if (!named || !ids) {
            table.warnings.push_back("A resource directory at RVA " + hex(d) + " is not in the file.");
            return;
        }
        std::size_t n = std::size_t{*named} + *ids;
        if (n > maxEntriesPerResourceDir) {
            table.warnings.push_back("A resource directory claims " + std::to_string(n) + " entries; only the first " +
                                     std::to_string(maxEntriesPerResourceDir) + " are read.");
            n = maxEntriesPerResourceDir;
        }
        for (std::size_t i = 0; i < n; ++i) {
            if (table.resources.size() >= maxResources) {
                table.warnings.push_back("Stopped after " + std::to_string(maxResources) + " resources.");
                return;
            }
            const std::uint64_t e = d + 16 + i * 8;
            const auto nameField = pe.readRvaAs<std::uint32_t>(e);
            const auto dataField = pe.readRvaAs<std::uint32_t>(e + 4);
            if (!nameField || !dataField) {
                table.warnings.push_back("A resource directory at RVA " + hex(d) + " is cut short.");
                return;
            }
            Resource here = path;
            if (level == 0) {
                here.type = label(*nameField, 0);
            } else if (level == 1) {
                here.name = label(*nameField, 1);
            } else {
                here.lang = *nameField & 0xFFFF;
            }
            if ((*dataField & 0x80000000u) != 0) {
                if (level >= 2) {
                    table.warnings.push_back("The resource tree is deeper than type/name/language at RVA " + hex(e) +
                                             "; that branch is skipped.");
                    continue;
                }
                walk(*dataField & 0x7FFFFFFFu, level + 1, here);
                continue;
            }
            const std::uint64_t leaf = base + *dataField;
            const auto rva = pe.readRvaAs<std::uint32_t>(leaf);
            const auto size = pe.readRvaAs<std::uint32_t>(leaf + 4);
            const auto codepage = pe.readRvaAs<std::uint32_t>(leaf + 8);
            if (!rva || !size || !codepage) {
                table.warnings.push_back("A resource data entry at RVA " + hex(leaf) + " is not in the file.");
                continue;
            }
            here.rva = *rva;
            here.size = *size;
            here.codepage = *codepage;
            table.resources.push_back(std::move(here));
        }
    }
};

} // namespace

ResourceTable PeFile::resources() const {
    ResourceTable table;
    const DataDirectory dir = directory(DirResource);
    if (dir.rva == 0) {
        return table;
    }
    ResourceWalker walker{*this, dir.rva, table, {}};
    walker.walk(0, 0, Resource{});
    return table;
}

// ---------------------------------------------------------------------------
// Debug directory: the CodeView record that names the PDB
// ---------------------------------------------------------------------------

std::optional<CodeView> PeFile::codeView() const {
    const DataDirectory dir = directory(DirDebug);
    if (dir.rva == 0) {
        return std::nullopt;
    }
    const std::size_t count = std::min<std::size_t>(dir.size / 28, 64);
    for (std::size_t i = 0; i < count; ++i) {
        const std::uint64_t e = std::uint64_t{dir.rva} + i * 28;
        const auto type = readRvaAs<std::uint32_t>(e + 12);
        const auto size = readRvaAs<std::uint32_t>(e + 16);
        const auto pointer = readRvaAs<std::uint32_t>(e + 24);
        if (!type || !size || !pointer) {
            return std::nullopt;
        }
        if (*type != 2 || *size < 24) { // IMAGE_DEBUG_TYPE_CODEVIEW
            continue;
        }
        const ByteView v = view();
        if (v.read<std::uint32_t>(*pointer) != std::uint32_t{0x53445352}) { // "RSDS"
            continue;
        }
        const auto d1 = v.read<std::uint32_t>(*pointer + 4ull);
        const auto d2 = v.read<std::uint16_t>(*pointer + 8ull);
        const auto d3 = v.read<std::uint16_t>(*pointer + 10ull);
        const auto d4 = v.slice(*pointer + 12ull, 8);
        const auto age = v.read<std::uint32_t>(*pointer + 20ull);
        const auto path = v.cstring(*pointer + 24ull, std::min<std::uint32_t>(*size - 24, 1024));
        if (!d1 || !d2 || !d3 || d4.size() != 8 || !age || !path) {
            continue;
        }
        char guid[40];
        std::snprintf(guid, sizeof(guid), "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X", *d1, *d2, *d3, d4[0], d4[1], d4[2],
                      d4[3], d4[4], d4[5], d4[6], d4[7]);
        return CodeView{printable(*path), guid, *age};
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// .pdata
// ---------------------------------------------------------------------------

std::optional<FunctionRange> PeFile::functionContaining(std::uint32_t rva) const {
    if (arch() != Arch::X64) {
        return std::nullopt;
    }
    const DataDirectory dir = directory(DirException);
    const std::size_t count = std::min<std::size_t>(dir.size / 12, 1u << 22);
    if (dir.rva == 0 || count == 0) {
        return std::nullopt;
    }
    // The table is sorted by BeginAddress: find the last entry that begins at
    // or before rva.
    std::size_t lo = 0;
    std::size_t hi = count;
    while (lo < hi) {
        const std::size_t mid = lo + (hi - lo) / 2;
        const auto begin = readRvaAs<std::uint32_t>(std::uint64_t{dir.rva} + mid * 12);
        if (!begin) {
            return std::nullopt;
        }
        if (*begin <= rva) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo == 0) {
        return std::nullopt;
    }
    std::uint64_t entry = std::uint64_t{dir.rva} + (lo - 1) * 12;
    auto begin = readRvaAs<std::uint32_t>(entry);
    auto end = readRvaAs<std::uint32_t>(entry + 4);
    if (!begin || !end || rva >= *end) {
        return std::nullopt;
    }
    // A function split by the compiler has fragments whose unwind info is
    // chained to the primary entry. Follow the chain, so the answer is the
    // function's real start rather than the start of a cold block.
    for (int hop = 0; hop < 32; ++hop) {
        const auto unwind = readRvaAs<std::uint32_t>(entry + 8);
        if (!unwind) {
            break;
        }
        std::uint64_t next = 0;
        if ((*unwind & 1) != 0) {
            next = *unwind & ~1u; // points straight at another RUNTIME_FUNCTION
        } else {
            const auto header = readRvaAs<std::uint8_t>(*unwind);
            const auto codes = readRvaAs<std::uint8_t>(*unwind + 2ull);
            if (!header || !codes || ((*header >> 3) & 0x4) == 0) { // UNW_FLAG_CHAININFO
                break;
            }
            const std::uint32_t slots = (*codes + 1u) & ~1u;
            next = *unwind + 4ull + 2ull * slots;
        }
        const auto b = readRvaAs<std::uint32_t>(next);
        const auto e = readRvaAs<std::uint32_t>(next + 4);
        if (!b || !e) {
            break;
        }
        entry = next;
        begin = b;
        end = e;
    }
    return FunctionRange{*begin, *end};
}

} // namespace pemcp
