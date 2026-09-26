#include "mcp/Tools.h"

#include "pe/Disasm.h"
#include "pe/Hash.h"
#include "pe/PeFile.h"
#include "pe/Strings.h"

#include <sigscan/sigscan.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <format>
#include <functional>
#include <map>
#include <optional>
#include <stdexcept>
#include <unordered_map>

namespace pemcp::mcp {

std::string dumpCompact(const Json& value) {
    return value.dump(-1, ' ', false, Json::error_handler_t::replace);
}

namespace {

// A bad argument or an unusable file. Caught in Session::call and returned as
// a tool error, so the model reads the sentence and can correct itself.
struct ToolError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

[[noreturn]] void fail(const std::string& message) {
    throw ToolError(message);
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

Json object(Json properties, std::vector<std::string> required = {}) {
    Json schema = {{"type", "object"}, {"properties", std::move(properties)}};
    if (!required.empty()) {
        schema["required"] = required;
    }
    schema["additionalProperties"] = false;
    return schema;
}

Json str(const std::string& description) {
    return {{"type", "string"}, {"description", description}};
}

Json address(const std::string& description) {
    return {{"type", Json::array({"string", "integer"})},
            {"description", description + " A string is read as hex, with or without 0x; an integer as itself."}};
}

Json integer(const std::string& description, std::int64_t lo, std::int64_t hi, std::int64_t def) {
    return {{"type", "integer"}, {"description", description}, {"minimum", lo}, {"maximum", hi}, {"default", def}};
}

Json boolean(const std::string& description) {
    return {{"type", "boolean"}, {"description", description}, {"default", false}};
}

const Json fileProp = str("Id of an open file, such as \"f1\". May be left out when exactly one file is open.");
const Json cursorProp = str("The `next` value from the previous page. Leave out for the first page.");

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

std::uint64_t parseHex(const std::string& text, const std::string& key) {
    std::string digits;
    std::size_t i = 0;
    while (i < text.size() && text[i] == ' ') {
        ++i;
    }
    if (i + 1 < text.size() && text[i] == '0' && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
        i += 2;
    }
    for (; i < text.size(); ++i) {
        const char c = text[i];
        if (c == '`' || c == '_' || c == ' ') {
            continue; // 00007FF6`12340000, as x64dbg and WinDbg print it
        }
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            fail(key + " \"" + text + "\" is not a hex number.");
        }
        digits += c;
    }
    if (digits.empty() || digits.size() > 16) {
        fail(key + " \"" + text + "\" is not a hex number of 1 to 16 digits.");
    }
    return std::stoull(digits, nullptr, 16);
}

std::optional<std::uint64_t> optAddress(const Json& args, const std::string& key) {
    if (!args.contains(key) || args.at(key).is_null()) {
        return std::nullopt;
    }
    const Json& v = args.at(key);
    if (v.is_number_unsigned()) {
        return v.get<std::uint64_t>();
    }
    if (v.is_number_integer()) {
        const auto i = v.get<std::int64_t>();
        if (i < 0) {
            fail(key + " must not be negative.");
        }
        return static_cast<std::uint64_t>(i);
    }
    if (v.is_string()) {
        return parseHex(v.get<std::string>(), key);
    }
    fail(key + " must be a hex string such as \"0x1A2B\" or an integer.");
}

std::optional<std::int64_t> optInteger(const Json& args, const std::string& key) {
    if (!args.contains(key) || args.at(key).is_null()) {
        return std::nullopt;
    }
    const Json& v = args.at(key);
    if (v.is_number_integer()) {
        return v.get<std::int64_t>();
    }
    if (v.is_string()) {
        const auto s = v.get<std::string>();
        if (!s.empty() && s.size() < 19 && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; })) {
            return std::stoll(s);
        }
    }
    fail(key + " must be an integer.");
}

// A limit or count: out-of-range values are clamped, not refused, because a
// model asking for 5000 rows is better served by the maximum and a cursor.
std::size_t clampedCount(const Json& args, const std::string& key, std::int64_t def, std::int64_t hi) {
    const std::int64_t v = optInteger(args, key).value_or(def);
    return static_cast<std::size_t>(std::clamp<std::int64_t>(v, 1, hi));
}

std::optional<std::string> optString(const Json& args, const std::string& key) {
    if (!args.contains(key) || args.at(key).is_null()) {
        return std::nullopt;
    }
    if (!args.at(key).is_string()) {
        fail(key + " must be a string.");
    }
    return args.at(key).get<std::string>();
}

bool optBool(const Json& args, const std::string& key) {
    if (!args.contains(key) || args.at(key).is_null()) {
        return false;
    }
    if (!args.at(key).is_boolean()) {
        fail(key + " must be true or false.");
    }
    return args.at(key).get<bool>();
}

std::size_t cursorIndex(const Json& args) {
    if (!args.contains("cursor") || args.at("cursor").is_null()) {
        return 0;
    }
    const Json& v = args.at("cursor");
    if (v.is_number_unsigned()) {
        return v.get<std::size_t>();
    }
    if (v.is_string()) {
        const auto s = v.get<std::string>();
        if (!s.empty() && s.size() < 12 && std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; })) {
            return static_cast<std::size_t>(std::stoull(s));
        }
    }
    fail("cursor must be the `next` value from a previous page of this tool.");
}

std::string lower(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

bool containsNoCase(const std::string& haystack, const std::string& needleLower) {
    return needleLower.empty() || lower(haystack).find(needleLower) != std::string::npos;
}

// ---------------------------------------------------------------------------
// Paging
// ---------------------------------------------------------------------------

struct ItemList {
    std::vector<Json> items;
    bool capped = false; // the collection stopped at its ceiling
};

// Puts items[start...] into head["items"] until `limit` rows or the byte
// ceiling, whichever comes first, and sets `next` to resume from there.
Json pageOf(Json head, const ItemList& list, std::size_t start, std::size_t limit) {
    if (start > list.items.size()) {
        fail("cursor " + std::to_string(start) + " is past the end of the " + std::to_string(list.items.size()) + " results.");
    }
    std::size_t used = dumpCompact(head).size() + 64;
    Json rows = Json::array();
    std::size_t i = start;
    for (; i < list.items.size() && rows.size() < limit; ++i) {
        const std::size_t n = dumpCompact(list.items[i]).size() + 1;
        if (!rows.empty() && used + n > Session::maxResultBytes) {
            break;
        }
        used += n;
        rows.push_back(list.items[i]);
    }
    head["total"] = list.items.size();
    if (list.capped) {
        head["total_capped"] = true;
    }
    head["items"] = std::move(rows);
    head["next"] = i < list.items.size() ? Json(std::to_string(i)) : Json(nullptr);
    return head;
}

void addWarnings(Json& out, const std::vector<std::string>& warnings) {
    if (warnings.empty()) {
        return;
    }
    Json list = Json::array();
    for (std::size_t i = 0; i < warnings.size() && i < 8; ++i) {
        list.push_back(warnings[i]);
    }
    if (warnings.size() > 8) {
        list.push_back("... and " + std::to_string(warnings.size() - 8) + " more.");
    }
    out["warnings"] = std::move(list);
}

double entropy(std::span<const std::uint8_t> bytes) {
    if (bytes.empty()) {
        return 0.0;
    }
    std::size_t counts[256] = {};
    for (std::uint8_t b : bytes) {
        ++counts[b];
    }
    double e = 0.0;
    for (std::size_t c : counts) {
        if (c != 0) {
            const double p = static_cast<double>(c) / static_cast<double>(bytes.size());
            e -= p * std::log2(p);
        }
    }
    return std::round(e * 100.0) / 100.0;
}

std::string sectionFlags(const Section& s) {
    std::string f = "---";
    if (s.readable()) {
        f[0] = 'r';
    }
    if (s.writable()) {
        f[1] = 'w';
    }
    if (s.executable()) {
        f[2] = 'x';
    }
    return f;
}

// Printable ASCII, plus the whitespace a format string ends with.
bool printableAscii(std::uint8_t b) {
    return (b >= 0x20 && b < 0x7F) || b == '\t' || b == '\r' || b == '\n';
}

// A short quoted preview when `rva` holds a string, for disassembly notes.
std::optional<std::string> stringPreview(const PeFile& pe, std::uint32_t rva) {
    constexpr std::size_t shown = 60;
    const auto b = pe.readRva(rva, 256);
    std::size_t n = 0;
    while (n < b.size() && printableAscii(b[n])) {
        ++n;
    }
    if (n >= 4 && n < b.size() && b[n] == 0) {
        std::string text(reinterpret_cast<const char*>(b.data()), std::min(n, shown));
        return "\"" + text + (n > shown ? "...\"" : "\"");
    }
    std::size_t m = 0;
    while (2 * m + 1 < b.size() && printableAscii(b[2 * m]) && b[2 * m + 1] == 0) {
        ++m;
    }
    if (m >= 4) {
        std::string text;
        for (std::size_t i = 0; i < std::min(m, shown); ++i) {
            text += static_cast<char>(b[2 * i]);
        }
        return "L\"" + text + (m > shown ? "...\"" : "\"");
    }
    return std::nullopt;
}

} // namespace

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

struct Session::Impl {
    struct OpenFile {
        std::string id;
        std::filesystem::path path;
        PeFile pe;

        // Built on first use by disassemble's notes.
        bool namesBuilt = false;
        std::unordered_map<std::uint32_t, std::string> importBySlot;
        std::unordered_map<std::uint32_t, std::string> exportByRva;

        // The last full result list, so paging through a big xref or string
        // list does not redo the sweep for every page.
        std::string cacheKey;
        ItemList cacheItems;
    };

    using Handler = Json (Impl::*)(const Json&);

    std::vector<ToolSpec> specs;
    std::map<std::string, Handler> handlers;
    std::vector<std::unique_ptr<OpenFile>> files;
    std::vector<std::string> startupErrors;
    unsigned nextId = 1;

    Impl();
    void add(std::string name, std::string description, Json schema, Handler handler) {
        handlers[name] = handler;
        specs.push_back({std::move(name), std::move(description), std::move(schema)});
    }

    // --- helpers -----------------------------------------------------------

    OpenFile& fileArg(const Json& args) {
        const auto id = optString(args, "file");
        if (!id) {
            if (files.empty()) {
                fail("No file is open. Call open_file with a path first.");
            }
            if (files.size() > 1) {
                std::string ids;
                for (const auto& f : files) {
                    ids += (ids.empty() ? "" : ", ") + f->id;
                }
                fail("Several files are open (" + ids + "); pass file to say which.");
            }
            return *files.front();
        }
        for (auto& f : files) {
            if (f->id == *id) {
                return *f;
            }
        }
        fail("No open file has the id \"" + *id + "\"." + (files.empty() ? " No file is open." : " Call list_files to see the ids."));
    }

    static Json summary(const OpenFile& f) {
        const PeFile& pe = f.pe;
        Json s = {{"id", f.id},
                  {"path", std::string(reinterpret_cast<const char*>(f.path.u8string().c_str()))},
                  {"format", pe.is64() ? "PE32+" : "PE32"},
                  {"machine", pe.machineName()},
                  {"size", pe.bytes().size()},
                  {"image_base", hex(pe.imageBase())},
                  {"entry", hex(pe.entryPoint())},
                  {"sections", pe.sections().size()}};
        return s;
    }

    // An address argument resolved to an RVA: `rva` as given, or `va` minus
    // the image base. Exactly one of the two may be passed.
    static std::optional<std::uint32_t> rvaArg(const PeFile& pe, const Json& args) {
        const auto rva = optAddress(args, "rva");
        const auto va = optAddress(args, "va");
        if (rva && va) {
            fail("Pass rva or va, not both.");
        }
        if (rva) {
            if (*rva > 0xFFFFFFFFull) {
                fail("rva " + hex(*rva) + " is larger than any RVA; did you mean va?");
            }
            return static_cast<std::uint32_t>(*rva);
        }
        if (va) {
            const auto r = pe.vaToRva(*va);
            if (!r) {
                fail("va " + hex(*va) + " is not inside this image, whose base is " + hex(pe.imageBase()) + ".");
            }
            return r;
        }
        return std::nullopt;
    }

    static void needX86(const PeFile& pe, const char* tool) {
        if (pe.arch() == Arch::Other) {
            fail(std::string(tool) + " decodes x86 and x64 code only; this file's machine is " + pe.machineName() + ".");
        }
    }

    const ItemList& cached(OpenFile& f, const std::string& tool, const Json& args, const std::function<ItemList()>& build) {
        Json keyArgs = args;
        keyArgs.erase("cursor");
        keyArgs.erase("limit");
        keyArgs.erase("file");
        const std::string key = tool + dumpCompact(keyArgs);
        if (f.cacheKey != key) {
            f.cacheItems = build();
            f.cacheKey = key;
        }
        return f.cacheItems;
    }

    void buildNames(OpenFile& f) {
        if (f.namesBuilt) {
            return;
        }
        for (const Import& imp : f.pe.imports().imports) {
            f.importBySlot.emplace(imp.iatRva, imp.dll + "!" + (imp.byOrdinal ? "#" + std::to_string(imp.ordinal) : imp.name));
        }
        for (const Export& e : f.pe.exports().exports) {
            if (e.forwarder.empty()) {
                f.exportByRva.emplace(e.rva, e.name.empty() ? "#" + std::to_string(e.ordinal) : e.name);
            }
        }
        f.namesBuilt = true;
    }

    std::optional<std::string> noteFor(OpenFile& f, std::uint32_t rva) {
        buildNames(f);
        if (auto it = f.importBySlot.find(rva); it != f.importBySlot.end()) {
            return it->second;
        }
        if (auto it = f.exportByRva.find(rva); it != f.exportByRva.end()) {
            return "export " + it->second;
        }
        return stringPreview(f.pe, rva);
    }

    // --- tools -------------------------------------------------------------

    Json openFile(const Json& args);
    Json closeFile(const Json& args);
    Json listFiles(const Json& args);
    Json headers(const Json& args);
    Json sections(const Json& args);
    Json imports(const Json& args);
    Json exports(const Json& args);
    Json strings(const Json& args);
    Json disassemble(const Json& args);
    Json xrefsTo(const Json& args);
    Json findPattern(const Json& args);
    Json readBytes(const Json& args);
    Json hash(const Json& args);
    Json rvaToOffset(const Json& args);
    Json offsetToRva(const Json& args);
    Json tlsCallbacks(const Json& args);
    Json resources(const Json& args);

    Json open(const std::filesystem::path& given);
};

Session::Impl::Impl() {
    add("open_file",
        "Open a PE file (exe, dll, sys) read-only and return its id. Several files can be open at once, so two builds can be "
        "compared. Opening a file that is already open returns its existing id.",
        object({{"path", str("Path to the file. A relative path is resolved against the server's working directory.")}}, {"path"}),
        &Impl::openFile);
    add("close_file", "Close an open file and forget its id.", object({{"file", str("Id of the file to close.")}}, {"file"}),
        &Impl::closeFile);
    add("list_files", "List the open files with their ids, format, machine, image base and entry point.", object(Json::object()),
        &Impl::listFiles);
    add("headers",
        "The PE headers: format, machine, timestamp, image base, entry point, subsystem, characteristics, mitigations "
        "(ASLR, DEP, CFG), non-empty data directories, the PDB path from the debug directory, and any overlay.",
        object({{"file", fileProp}}), &Impl::headers);
    add("sections",
        "The section table: name, RVA, virtual size, file offset, raw size, r/w/x flags and entropy. Entropy near 8 suggests "
        "packed or encrypted data.",
        object({{"file", fileProp}, {"limit", integer("Rows per page.", 1, 96, 96)}, {"cursor", cursorProp}}), &Impl::sections);
    add("imports",
        "Imported functions, including delay-loaded ones, with the RVA of each IAT slot. Code calls an import through its "
        "slot, so pass a slot RVA to xrefs_to to find the callers. The first page also lists every DLL with a count.",
        object({{"file", fileProp},
                {"dll", str("Only DLLs whose name contains this text (case-insensitive).")},
                {"filter", str("Only functions whose name contains this text (case-insensitive).")},
                {"limit", integer("Rows per page.", 1, 1000, 100)},
                {"cursor", cursorProp}}),
        &Impl::imports);
    add("exports", "Exported functions: ordinal, name and RVA, or the forwarder string for a forwarded export.",
        object({{"file", fileProp},
                {"filter", str("Only exports whose name contains this text (case-insensitive).")},
                {"limit", integer("Rows per page.", 1, 1000, 100)},
                {"cursor", cursorProp}}),
        &Impl::exports);
    add("strings",
        "Printable ASCII and UTF-16LE strings in the sections' file data, with the RVA of each. Pass an RVA from here to "
        "xrefs_to to find the code that uses the string. Executable sections are skipped unless include_code is true or "
        "section names one, because code bytes read as short junk strings. Text longer than 200 characters is cut, and "
        "len gives the full length.",
        object({{"file", fileProp},
                {"min_length", integer("Shortest run to report, in characters.", 2, 200, 5)},
                {"encoding", {{"type", "string"}, {"enum", {"both", "ascii", "utf16"}}, {"default", "both"}}},
                {"section", str("Only this section, by exact name, such as \".rdata\".")},
                {"include_code", boolean("Also scan executable sections.")},
                {"filter", str("Only strings containing this text (case-insensitive).")},
                {"limit", integer("Rows per page.", 1, 1000, 100)},
                {"cursor", cursorProp}}),
        &Impl::strings);
    add("disassemble",
        "Disassemble x86 or x64 code starting at an RVA or VA. Each row has the RVA, bytes and Intel-syntax text; an "
        "instruction that refers into the image also has ref (the target RVA) and, where known, a note naming the import, "
        "export or string there. With function true on an x64 file, starts at the beginning of the function containing the "
        "address (from .pdata) and stops at its end.",
        object({{"file", fileProp},
                {"rva", address("Start address as an RVA.")},
                {"va", address("Start address as a VA (image base + RVA).")},
                {"count", integer("Instructions to decode.", 1, 200, 20)},
                {"function", boolean("Disassemble the whole function containing the address (x64 only).")},
                {"cursor", str("The `next` value from the previous call, to continue where it stopped.")}}),
        &Impl::disassemble);
    add("xrefs_to",
        "Find the code that refers to an RVA: relative calls and jumps, RIP-relative operands (lea, mov) and absolute "
        "addresses, found by decoding every executable section. On x64 each result names the function it is in. Use it on "
        "a string's RVA to find the code that uses the string, or on an IAT slot to find the callers of an import.",
        object({{"file", fileProp},
                {"rva", address("Target as an RVA.")},
                {"va", address("Target as a VA.")},
                {"size", integer("Count references anywhere in [target, target + size), for a structure or array.", 1, 1 << 20, 1)},
                {"include_data", boolean("Also report pointer-sized values in data sections that point at the target, "
                                         "such as vtable and table entries.")},
                {"limit", integer("Rows per page.", 1, 500, 50)},
                {"cursor", cursorProp}}),
        &Impl::xrefsTo);
    add("find_pattern",
        "Search the file for a byte signature in any common form: x64dbg (48 8B ?? ??), IDA (48 8B ? ?), code and mask "
        "(\"\\x48\\x8B\" \"xx\"), a C++ array with mask, or a Cheat Engine / Pointer Lab aobscanmodule(...) line. Returns "
        "every match with its RVA and file offset, and the total, so a signature can be checked for uniqueness.",
        object({{"file", fileProp},
                {"pattern", str("The signature.")},
                {"section", str("Only matches inside this section, by exact name.")},
                {"limit", integer("Rows per page.", 1, 1000, 50)},
                {"cursor", cursorProp}},
               {"pattern"}),
        &Impl::findPattern);
    add("read_bytes", "Read raw bytes as hex, by RVA, VA or file offset. Stops early at the end of a section's file data.",
        object({{"file", fileProp},
                {"rva", address("Start as an RVA.")},
                {"va", address("Start as a VA.")},
                {"offset", address("Start as a file offset.")},
                {"length", integer("Bytes to read.", 1, 4096, 256)}}),
        &Impl::readBytes);
    add("hash", "SHA-256 of the whole file and of each section's file data, and the imphash (MD5 of the import list).",
        object({{"file", fileProp}}), &Impl::hash);
    add("rva_to_offset", "Convert an RVA or VA to a file offset, and name the section it is in.",
        object({{"file", fileProp}, {"rva", address("The RVA.")}, {"va", address("The VA.")}}), &Impl::rvaToOffset);
    add("offset_to_rva", "Convert a file offset to an RVA and VA, and name the section it is in.",
        object({{"file", fileProp}, {"offset", address("The file offset.")}}, {"offset"}), &Impl::offsetToRva);
    add("tls_callbacks",
        "The TLS directory and its callbacks. TLS callbacks run before the entry point, which is why they are worth checking.",
        object({{"file", fileProp}}), &Impl::tlsCallbacks);
    add("resources", "The resource tree as type / name / language rows, with the RVA and size of each resource's data.",
        object({{"file", fileProp},
                {"type", str("Only this type, such as \"MANIFEST\", \"VERSION\", \"#300\" or a named type.")},
                {"limit", integer("Rows per page.", 1, 1000, 100)},
                {"cursor", cursorProp}}),
        &Impl::resources);
}

// --- files -------------------------------------------------------------------

Json Session::Impl::open(const std::filesystem::path& given) {
    std::error_code ec;
    std::filesystem::path path = std::filesystem::absolute(given, ec);
    if (ec) {
        path = given;
    }
    path = path.lexically_normal();
    for (const auto& f : files) {
        std::error_code same;
        if (f->path == path || std::filesystem::equivalent(f->path, path, same)) {
            Json s = summary(*f);
            s["already_open"] = true;
            return s;
        }
    }
    if (files.size() >= maxOpenFiles) {
        fail("Sixteen files are already open; close one first.");
    }
    std::string error;
    auto pe = PeFile::load(path, error);
    if (!pe) {
        fail(std::string(reinterpret_cast<const char*>(path.u8string().c_str())) + ": " + error);
    }
    auto f = std::make_unique<OpenFile>(OpenFile{"f" + std::to_string(nextId++), path, std::move(*pe)});
    Json s = summary(*f);
    addWarnings(s, f->pe.headerWarnings());
    files.push_back(std::move(f));
    return s;
}

Json Session::Impl::openFile(const Json& args) {
    const auto path = optString(args, "path");
    if (!path || path->empty()) {
        fail("path is required.");
    }
    return open(std::filesystem::path(std::u8string(reinterpret_cast<const char8_t*>(path->data()), path->size())));
}

Json Session::Impl::closeFile(const Json& args) {
    const auto id = optString(args, "file");
    if (!id) {
        fail("file is required: the id of the file to close.");
    }
    for (auto it = files.begin(); it != files.end(); ++it) {
        if ((*it)->id == *id) {
            files.erase(it);
            return {{"closed", *id}};
        }
    }
    fail("No open file has the id \"" + *id + "\".");
}

Json Session::Impl::listFiles(const Json&) {
    Json list = Json::array();
    for (const auto& f : files) {
        list.push_back(summary(*f));
    }
    Json out = {{"files", std::move(list)}};
    if (!startupErrors.empty()) {
        out["startup_errors"] = startupErrors;
    }
    return out;
}

// --- headers and tables --------------------------------------------------------

Json Session::Impl::headers(const Json& args) {
    OpenFile& f = fileArg(args);
    const PeFile& pe = f.pe;
    const auto& h = pe.fields();

    Json characteristics = Json::array();
    static constexpr std::pair<std::uint16_t, const char*> fileFlags[] = {
        {0x0001, "RELOCS_STRIPPED"}, {0x0002, "EXECUTABLE_IMAGE"}, {0x0020, "LARGE_ADDRESS_AWARE"},
        {0x0100, "32BIT_MACHINE"},   {0x0200, "DEBUG_STRIPPED"},   {0x1000, "SYSTEM"},
        {0x2000, "DLL"},
    };
    for (const auto& [bit, name] : fileFlags) {
        if ((h.characteristics & bit) != 0) {
            characteristics.push_back(name);
        }
    }
    Json dllFlags = Json::array();
    static constexpr std::pair<std::uint16_t, const char*> mitigations[] = {
        {0x0020, "HIGH_ENTROPY_VA"}, {0x0040, "DYNAMIC_BASE"}, {0x0080, "FORCE_INTEGRITY"}, {0x0100, "NX_COMPAT"},
        {0x0200, "NO_ISOLATION"},    {0x0400, "NO_SEH"},       {0x0800, "NO_BIND"},         {0x1000, "APPCONTAINER"},
        {0x2000, "WDM_DRIVER"},      {0x4000, "GUARD_CF"},     {0x8000, "TERMINAL_SERVER_AWARE"},
    };
    for (const auto& [bit, name] : mitigations) {
        if ((h.dllCharacteristics & bit) != 0) {
            dllFlags.push_back(name);
        }
    }
    const char* subsystem = "unknown";
    switch (h.subsystem) {
    case 1: subsystem = "native"; break;
    case 2: subsystem = "windows_gui"; break;
    case 3: subsystem = "windows_cui"; break;
    case 9: subsystem = "windows_ce_gui"; break;
    case 10: subsystem = "efi_application"; break;
    case 11: subsystem = "efi_boot_service_driver"; break;
    case 12: subsystem = "efi_runtime_driver"; break;
    case 14: subsystem = "xbox"; break;
    case 16: subsystem = "windows_boot_application"; break;
    default: break;
    }
    Json dirs = Json::array();
    for (std::size_t i = 0; i < pe.directories().size(); ++i) {
        const auto& d = pe.directories()[i];
        if (d.rva != 0 || d.size != 0) {
            dirs.push_back({{"name", directoryName(i)}, {"rva", hex(d.rva)}, {"size", d.size}});
        }
    }

    Json out = {{"format", pe.is64() ? "PE32+" : "PE32"},
                {"machine", pe.machineName()},
                {"machine_id", hex(pe.machine())},
                {"timestamp", hex(h.timestamp)},
                {"timestamp_utc", std::format("{:%Y-%m-%dT%H:%M:%SZ}", std::chrono::sys_seconds{std::chrono::seconds{h.timestamp}})},
                {"image_base", hex(pe.imageBase())},
                {"entry", hex(pe.entryPoint())},
                {"subsystem", subsystem},
                {"characteristics", std::move(characteristics)},
                {"dll_characteristics", std::move(dllFlags)},
                {"size_of_image", hex(pe.sizeOfImage())},
                {"size_of_headers", hex(pe.sizeOfHeaders())},
                {"checksum", hex(h.checksum)},
                {"section_alignment", hex(h.sectionAlignment)},
                {"file_alignment", hex(h.fileAlignment)},
                {"linker", std::to_string(h.linkerMajor) + "." + std::to_string(h.linkerMinor)},
                {"os_version", std::to_string(h.osMajor) + "." + std::to_string(h.osMinor)},
                {"sections", pe.sections().size()},
                {"directories", std::move(dirs)}};
    if (auto cv = pe.codeView()) {
        out["pdb"] = {{"path", cv->pdbPath}, {"guid", cv->guid}, {"age", cv->age}};
    }
    if (auto ov = pe.overlay()) {
        out["overlay"] = {{"offset", hex(ov->first)}, {"size", ov->second}};
    }
    addWarnings(out, pe.headerWarnings());
    return out;
}

Json Session::Impl::sections(const Json& args) {
    OpenFile& f = fileArg(args);
    const PeFile& pe = f.pe;
    ItemList list;
    for (const Section& s : pe.sections()) {
        list.items.push_back({{"name", s.name},
                              {"rva", hex(s.rva)},
                              {"vsize", s.virtualSize},
                              {"offset", hex(s.rawOffset)},
                              {"raw_size", s.rawSize},
                              {"flags", sectionFlags(s)},
                              {"entropy", entropy(pe.view().slice(s.rawOffset, s.rawSize))}});
    }
    return pageOf(Json::object(), list, cursorIndex(args), clampedCount(args, "limit", 96, 96));
}

Json Session::Impl::imports(const Json& args) {
    OpenFile& f = fileArg(args);
    const auto dllFilter = lower(optString(args, "dll").value_or(""));
    const auto nameFilter = lower(optString(args, "filter").value_or(""));
    const std::size_t start = cursorIndex(args);
    const ImportTable table = f.pe.imports();

    ItemList list;
    for (const Import& imp : table.imports) {
        if (!containsNoCase(imp.dll, dllFilter)) {
            continue;
        }
        if (!nameFilter.empty() && (imp.byOrdinal || !containsNoCase(imp.name, nameFilter))) {
            continue;
        }
        Json row = {{"dll", imp.dll}};
        if (imp.byOrdinal) {
            row["ordinal"] = imp.ordinal;
        } else {
            row["name"] = imp.name;
        }
        row["iat"] = hex(imp.iatRva);
        if (imp.delay) {
            row["delay"] = true;
        }
        list.items.push_back(std::move(row));
    }
    Json head = Json::object();
    if (start == 0) {
        Json dlls = Json::array();
        for (const Import& imp : table.imports) {
            if (dlls.empty() || dlls.back()["name"] != imp.dll || dlls.back().contains("delay") != imp.delay) {
                Json d = {{"name", imp.dll}, {"count", 0}};
                if (imp.delay) {
                    d["delay"] = true;
                }
                dlls.push_back(std::move(d));
            }
            dlls.back()["count"] = dlls.back()["count"].get<int>() + 1;
        }
        // A corrupt table can name thousands of DLLs; the summary is for
        // orientation, so it stops well inside the size cap.
        constexpr std::size_t maxDllsShown = 100;
        if (dlls.size() > maxDllsShown) {
            head["dll_count"] = dlls.size();
            dlls.erase(dlls.begin() + maxDllsShown, dlls.end());
        }
        head["dlls"] = std::move(dlls);
        addWarnings(head, table.warnings);
    }
    return pageOf(std::move(head), list, start, clampedCount(args, "limit", 100, 1000));
}

Json Session::Impl::exports(const Json& args) {
    OpenFile& f = fileArg(args);
    const auto filter = lower(optString(args, "filter").value_or(""));
    const ExportTable table = f.pe.exports();
    ItemList list;
    for (const Export& e : table.exports) {
        if (!filter.empty() && !containsNoCase(e.name, filter)) {
            continue;
        }
        Json row = {{"ordinal", e.ordinal}};
        if (!e.name.empty()) {
            row["name"] = e.name;
        }
        if (e.forwarder.empty()) {
            row["rva"] = hex(e.rva);
        } else {
            row["forward"] = e.forwarder;
        }
        list.items.push_back(std::move(row));
    }
    Json head = Json::object();
    if (table.present) {
        head["dll_name"] = table.dllName;
        head["ordinal_base"] = table.ordinalBase;
    }
    addWarnings(head, table.warnings);
    return pageOf(std::move(head), list, cursorIndex(args), clampedCount(args, "limit", 100, 1000));
}

Json Session::Impl::strings(const Json& args) {
    OpenFile& f = fileArg(args);
    const PeFile& pe = f.pe;
    StringScan scan;
    const auto minLength = optInteger(args, "min_length").value_or(5);
    if (minLength < 2 || minLength > 200) {
        fail("min_length must be from 2 to 200.");
    }
    scan.minLength = static_cast<std::size_t>(minLength);
    const auto encoding = optString(args, "encoding").value_or("both");
    if (encoding == "ascii") {
        scan.wide = false;
    } else if (encoding == "utf16") {
        scan.ascii = false;
    } else if (encoding != "both") {
        fail("encoding must be \"ascii\", \"utf16\" or \"both\".");
    }
    const auto section = optString(args, "section");
    if (section && !pe.sectionByName(*section)) {
        std::string names;
        for (const auto& s : pe.sections()) {
            names += (names.empty() ? "" : ", ") + s.name;
        }
        fail("There is no section named \"" + *section + "\". Sections: " + names + ".");
    }
    const auto filter = lower(optString(args, "filter").value_or(""));
    const bool includeCode = optBool(args, "include_code");

    const ItemList& list = cached(f, "strings", args, [&] {
        ItemList out;
        constexpr std::size_t ceiling = 200000;
        for (const Section& s : pe.sections()) {
            if (section ? s.name != *section : (s.executable() && !includeCode)) {
                continue;
            }
            for (const FoundString& fs : findStrings(pe.view().slice(s.rawOffset, s.rawSize), 0, scan)) {
                if (!filter.empty() && !containsNoCase(fs.text, filter)) {
                    continue;
                }
                if (out.items.size() >= ceiling) {
                    out.capped = true;
                    return out;
                }
                Json row = {{"rva", hex(s.rva + fs.offset)}, {"enc", fs.wide ? "utf16" : "ascii"}, {"text", fs.text}};
                if (fs.length > fs.text.size()) {
                    row["len"] = fs.length;
                }
                out.items.push_back(std::move(row));
            }
        }
        return out;
    });
    return pageOf(Json::object(), list, cursorIndex(args), clampedCount(args, "limit", 100, 1000));
}

// --- code ---------------------------------------------------------------------------

Json Session::Impl::disassemble(const Json& args) {
    OpenFile& f = fileArg(args);
    const PeFile& pe = f.pe;
    needX86(pe, "disassemble");
    const std::size_t count = clampedCount(args, "count", 20, 200);
    const bool wholeFunction = optBool(args, "function");

    std::optional<std::uint32_t> start;
    const bool resuming = args.contains("cursor") && !args.at("cursor").is_null();
    if (resuming) {
        const auto c = optAddress(args, "cursor");
        if (*c > 0xFFFFFFFFull) {
            fail("cursor must be the `next` value from a previous disassemble call.");
        }
        start = static_cast<std::uint32_t>(*c);
    } else {
        start = rvaArg(pe, args);
    }
    if (!start) {
        fail("Pass rva or va to say where to start.");
    }
    std::uint64_t stop = ~0ull;
    Json head = Json::object();
    if (wholeFunction) {
        // Bounds come from .pdata. A function that never touches the stack
        // needs no unwind data and has no entry, and x86 has no table at
        // all; then this says so and starts at the address it was given,
        // rather than refusing and costing the agent a round trip.
        if (const auto fn = pe.functionContaining(*start)) {
            if (!resuming) {
                start = fn->begin;
            }
            stop = fn->end;
            head["function"] = {{"begin", hex(fn->begin)}, {"end", hex(fn->end)}};
        } else {
            head["function"] = nullptr;
            head["note"] = pe.arch() == Arch::X64
                               ? "No .pdata entry covers this address (a function that never touches the stack has none), "
                                 "so this starts at the given address."
                               : "An x86 file has no .pdata to give function bounds, so this starts at the given address.";
        }
    }
    if (pe.rvaToOffset(*start) == std::nullopt) {
        fail("RVA " + hex(*start) + " is not backed by the file (outside every section, or in zero-filled data).");
    }

    const Disassembler dis(pe.is64());
    std::vector<Json> rows;
    std::uint64_t rva = *start;
    bool ended = false;
    while (rows.size() < count) {
        if (rva >= stop) {
            ended = true;
            break;
        }
        const auto bytes = pe.readRva(rva, 15);
        if (bytes.empty()) {
            ended = true;
            break;
        }
        const std::uint64_t va = pe.imageBase() + rva;
        const Instruction ins = dis.decode(bytes, va, true);
        Json row = {{"rva", hex(rva)}, {"bytes", hexBytes(bytes.first(ins.length))}, {"text", ins.text}};
        for (const Reference& r : ins.refs) {
            const auto target = pe.vaToRva(r.va);
            if (!target || *target >= std::max<std::uint32_t>(pe.sizeOfImage(), 1)) {
                continue;
            }
            row["ref"] = hex(*target);
            if (auto note = noteFor(f, *target)) {
                row["note"] = *note;
            }
            break;
        }
        rows.push_back(std::move(row));
        rva += ins.length;
    }

    // Emit within the byte ceiling; whatever does not fit is where `next`
    // resumes.
    std::size_t used = dumpCompact(head).size() + 64;
    Json items = Json::array();
    std::optional<std::string> next;
    for (std::size_t i = 0; i < rows.size(); ++i) {
        const std::size_t n = dumpCompact(rows[i]).size() + 1;
        if (!items.empty() && used + n > Session::maxResultBytes) {
            next = rows[i]["rva"].get<std::string>();
            break;
        }
        used += n;
        items.push_back(std::move(rows[i]));
    }
    if (!next && !ended) {
        next = hex(rva);
    }
    head["items"] = std::move(items);
    head["next"] = next ? Json(*next) : Json(nullptr);
    return head;
}

Json Session::Impl::xrefsTo(const Json& args) {
    OpenFile& f = fileArg(args);
    const PeFile& pe = f.pe;
    needX86(pe, "xrefs_to");
    const auto target = rvaArg(pe, args);
    if (!target) {
        fail("Pass rva or va: the address to find references to.");
    }
    XrefQuery query;
    query.targetRva = *target;
    const auto size = optInteger(args, "size").value_or(1);
    if (size < 1 || size > (1 << 20)) {
        fail("size must be from 1 to 1048576.");
    }
    query.size = static_cast<std::uint32_t>(size);
    query.includeData = optBool(args, "include_data");

    const ItemList& list = cached(f, "xrefs_to", args, [&] {
        ItemList out;
        query.maxResults = 100001;
        auto refs = findXrefs(pe, query);
        if (refs.size() > 100000) {
            refs.resize(100000);
            out.capped = true;
        }
        for (const Xref& x : refs) {
            Json row = {{"rva", hex(x.rva)}, {"kind", refKindName(x.kind)}, {"text", x.text}};
            if (auto fn = pe.functionContaining(x.rva)) {
                row["function"] = hex(fn->begin);
            }
            out.items.push_back(std::move(row));
        }
        return out;
    });
    Json head = {{"target", hex(*target)}};
    if (auto note = noteFor(f, *target)) {
        head["note"] = *note;
    }
    return pageOf(std::move(head), list, cursorIndex(args), clampedCount(args, "limit", 50, 500));
}

Json Session::Impl::findPattern(const Json& args) {
    OpenFile& f = fileArg(args);
    const PeFile& pe = f.pe;
    const auto text = optString(args, "pattern");
    if (!text || text->empty()) {
        fail("pattern is required.");
    }
    const auto parsed = sigscan::parse(*text);
    if (!parsed) {
        fail("The pattern could not be read: " + parsed.error);
    }
    if (parsed.pattern.size() > 1024) {
        fail("The pattern is " + std::to_string(parsed.pattern.size()) + " bytes; the limit is 1024.");
    }
    const auto section = optString(args, "section");
    if (section && !pe.sectionByName(*section)) {
        fail("There is no section named \"" + *section + "\".");
    }

    const ItemList& list = cached(f, "find_pattern", args, [&] {
        ItemList out;
        constexpr std::size_t ceiling = 100000;
        const auto offsets = sigscan::findAll(std::span<const std::uint8_t>(pe.bytes()), parsed.pattern, 0);
        for (std::size_t off : offsets) {
            const Section* s = pe.sectionForOffset(off);
            if (section && (!s || s->name != *section)) {
                continue;
            }
            if (out.items.size() >= ceiling) {
                out.capped = true;
                break;
            }
            Json row = Json::object();
            if (auto rva = pe.offsetToRva(off)) {
                row["rva"] = hex(*rva);
            }
            row["offset"] = hex(off);
            row["section"] = s ? Json(s->name) : Json(pe.offsetToRva(off) ? "(headers)" : "(overlay)");
            out.items.push_back(std::move(row));
        }
        return out;
    });
    Json head = {{"pattern", sigscan::format(parsed.pattern, sigscan::Format::X64dbg)}};
    return pageOf(std::move(head), list, cursorIndex(args), clampedCount(args, "limit", 50, 1000));
}

Json Session::Impl::readBytes(const Json& args) {
    OpenFile& f = fileArg(args);
    const PeFile& pe = f.pe;
    const std::size_t length = clampedCount(args, "length", 256, 4096);
    const auto offset = optAddress(args, "offset");
    const auto rva = rvaArg(pe, args);
    if (offset && rva) {
        fail("Pass one of rva, va or offset.");
    }
    if (!offset && !rva) {
        fail("Pass rva, va or offset to say where to read.");
    }
    Json out = Json::object();
    std::span<const std::uint8_t> bytes;
    if (rva) {
        bytes = pe.readRva(*rva, length);
        if (bytes.empty()) {
            fail("RVA " + hex(*rva) + " is not backed by the file (outside every section, or in zero-filled data).");
        }
        out["rva"] = hex(*rva);
        out["offset"] = hex(*pe.rvaToOffset(*rva));
    } else {
        bytes = pe.view().slice(*offset, length);
        if (bytes.empty()) {
            fail("Offset " + hex(*offset) + " is past the end of the " + std::to_string(pe.bytes().size()) + "-byte file.");
        }
        if (auto r = pe.offsetToRva(*offset)) {
            out["rva"] = hex(*r);
        }
        out["offset"] = hex(*offset);
    }
    out["requested"] = length;
    out["length"] = bytes.size();
    out["hex"] = hexBytes(bytes);
    return out;
}

Json Session::Impl::hash(const Json& args) {
    OpenFile& f = fileArg(args);
    const PeFile& pe = f.pe;
    Json sections = Json::array();
    for (const Section& s : pe.sections()) {
        sections.push_back({{"name", s.name}, {"sha256", sha256Hex(pe.view().slice(s.rawOffset, s.rawSize))}});
    }
    const std::string imp = imphash(pe);
    return {{"size", pe.bytes().size()},
            {"sha256", sha256Hex(pe.bytes())},
            {"imphash", imp.empty() ? Json(nullptr) : Json(imp)},
            {"sections", std::move(sections)}};
}

Json Session::Impl::rvaToOffset(const Json& args) {
    OpenFile& f = fileArg(args);
    const PeFile& pe = f.pe;
    const auto rva = rvaArg(pe, args);
    if (!rva) {
        fail("Pass rva or va.");
    }
    const Section* s = pe.sectionForRva(*rva);
    const auto off = pe.rvaToOffset(*rva);
    if (!off) {
        if (s) {
            fail("RVA " + hex(*rva) + " is in " + s->name + " but past its file data; the loader zero-fills it, so it has no file offset.");
        }
        fail("RVA " + hex(*rva) + " is outside every section and past the headers.");
    }
    return {{"rva", hex(*rva)}, {"va", hex(pe.imageBase() + *rva)}, {"offset", hex(*off)}, {"section", s ? s->name : "(headers)"}};
}

Json Session::Impl::offsetToRva(const Json& args) {
    OpenFile& f = fileArg(args);
    const PeFile& pe = f.pe;
    const auto offset = optAddress(args, "offset");
    if (!offset) {
        fail("offset is required.");
    }
    if (*offset >= pe.bytes().size()) {
        fail("Offset " + hex(*offset) + " is past the end of the " + std::to_string(pe.bytes().size()) + "-byte file.");
    }
    const auto rva = pe.offsetToRva(*offset);
    if (!rva) {
        fail("Offset " + hex(*offset) + " is not mapped by the loader: it is in the overlay or in a gap between sections.");
    }
    const Section* s = pe.sectionForOffset(*offset);
    return {{"offset", hex(*offset)}, {"rva", hex(*rva)}, {"va", hex(pe.imageBase() + *rva)}, {"section", s ? s->name : "(headers)"}};
}

Json Session::Impl::tlsCallbacks(const Json& args) {
    OpenFile& f = fileArg(args);
    const PeFile& pe = f.pe;
    const TlsInfo tls = pe.tls();
    Json callbacks = Json::array();
    for (std::uint64_t va : tls.callbacks) {
        Json row = {{"va", hex(va)}};
        if (auto rva = pe.vaToRva(va)) {
            row["rva"] = hex(*rva);
            const Section* s = pe.sectionForRva(*rva);
            row["section"] = s ? Json(s->name) : Json(nullptr);
        }
        callbacks.push_back(std::move(row));
    }
    Json out = {{"present", tls.present}, {"callbacks", std::move(callbacks)}};
    if (tls.present) {
        out["index"] = hex(tls.indexVa);
        out["raw_data"] = {{"start", hex(tls.rawDataStart)}, {"end", hex(tls.rawDataEnd)}};
    }
    addWarnings(out, tls.warnings);
    return out;
}

Json Session::Impl::resources(const Json& args) {
    OpenFile& f = fileArg(args);
    const auto type = optString(args, "type");
    const ResourceTable table = f.pe.resources();
    ItemList list;
    for (const Resource& r : table.resources) {
        if (type && lower(r.type) != lower(*type)) {
            continue;
        }
        Json row = {{"type", r.type}, {"name", r.name}, {"lang", r.lang}, {"rva", hex(r.rva)}, {"size", r.size}};
        if (r.codepage != 0) {
            row["codepage"] = r.codepage;
        }
        list.items.push_back(std::move(row));
    }
    Json head = Json::object();
    addWarnings(head, table.warnings);
    return pageOf(std::move(head), list, cursorIndex(args), clampedCount(args, "limit", 100, 1000));
}

// ---------------------------------------------------------------------------

Session::Session() : impl_(std::make_unique<Impl>()) {}
Session::~Session() = default;

const std::vector<ToolSpec>& Session::tools() const {
    return impl_->specs;
}

bool Session::hasTool(const std::string& name) const {
    return impl_->handlers.contains(name);
}

CallResult Session::call(const std::string& name, const Json& arguments) {
    const auto it = impl_->handlers.find(name);
    if (it == impl_->handlers.end()) {
        return {false, "There is no tool called \"" + name + "\"."};
    }
    const Json args = arguments.is_null() ? Json::object() : arguments;
    try {
        if (!args.is_object()) {
            fail("arguments must be a JSON object.");
        }
        // Reject a misspelled argument rather than ignore it: "min_len"
        // silently falling back to the default is a wrong answer that looks
        // like a right one.
        const ToolSpec* spec = nullptr;
        for (const auto& s : impl_->specs) {
            if (s.name == name) {
                spec = &s;
            }
        }
        const Json& props = spec->inputSchema.at("properties");
        for (const auto& [key, value] : args.items()) {
            if (!props.contains(key)) {
                std::string accepted;
                for (const auto& [p, unused] : props.items()) {
                    accepted += (accepted.empty() ? "" : ", ") + p;
                }
                fail("Unknown argument \"" + key + "\". " + name + " takes: " + (accepted.empty() ? "nothing" : accepted) + ".");
            }
        }
        return {true, dumpCompact((impl_.get()->*(it->second))(args))};
    } catch (const ToolError& e) {
        return {false, e.what()};
    } catch (const std::bad_alloc&) {
        return {false, "Out of memory while running " + name + "."};
    } catch (const std::exception& e) {
        return {false, std::string("Internal error in ") + name + ": " + e.what()};
    }
}

std::string Session::openAtStartup(const std::filesystem::path& path) {
    try {
        (void)impl_->open(path);
        return {};
    } catch (const std::exception& e) {
        impl_->startupErrors.push_back(e.what());
        return e.what();
    }
}

} // namespace pemcp::mcp
