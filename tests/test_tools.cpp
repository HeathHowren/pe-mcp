#include "TestSupport.h"

#include <catch2/catch_test_macros.hpp>

#include <set>

using namespace testing;

namespace {

// One call per tool, with the arguments an agent would use. The outputs are
// compared with tests/golden/<arch>/<name>.json.
struct GoldenCall {
    const char* name;
    const char* tool;
    const char* args;
};

const GoldenCall goldenCalls[] = {
    {"headers", "headers", "{}"},
    {"sections", "sections", "{}"},
    {"imports", "imports", "{}"},
    {"exports", "exports", "{}"},
    {"strings", "strings", "{}"},
    {"strings_rdata_ascii", "strings", R"({"section":".rdata","encoding":"ascii","min_length":8})"},
    {"disassemble_main", "disassemble", R"({"rva":"0x1000","count":9})"},
    {"disassemble_function", "disassemble", R"({"va":"0x140001067","function":true})"},
    {"xrefs_string", "xrefs_to", R"({"rva":"0x2000"})"},
    {"xrefs_function", "xrefs_to", R"({"rva":"0x1040","include_data":true})"},
    {"xrefs_import", "xrefs_to", R"({"rva":"0x2080"})"},
    {"find_pattern", "find_pattern", R"({"pattern":"E8 ?? ?? ?? ??"})"},
    {"read_bytes", "read_bytes", R"({"rva":"0x1000","length":16})"},
    {"hash", "hash", "{}"},
    {"rva_to_offset", "rva_to_offset", R"({"rva":"0x2040"})"},
    {"offset_to_rva", "offset_to_rva", R"({"offset":"0x404"})"},
    {"tls_callbacks", "tls_callbacks", "{}"},
    {"resources", "resources", "{}"},
};

void runGolden(bool is64) {
    SyntheticSession s(is64);
    const std::string arch = is64 ? "x64" : "x86";
    for (const GoldenCall& g : goldenCalls) {
        std::string args = g.args;
        if (!is64) {
            // The same questions of the PE32 build: its image base is 0x400000
            // and it has no .pdata, so function mode is not asked of it.
            if (std::string(g.name) == "disassemble_function") {
                args = R"({"va":"0x401060","count":2})";
            }
        }
        const auto r = s.session.call(g.tool, Json::parse(args));
        INFO(arch << "/" << g.name << " -> " << r.text);
        REQUIRE(r.ok);
        checkGolden(arch + "/" + g.name, r.text);
    }
}

// Walks every page of a tool and returns all rows, checking each page fits.
std::vector<Json> allPages(Session& session, const std::string& tool, Json args) {
    std::vector<Json> rows;
    for (int guard = 0; guard < 10000; ++guard) {
        const auto r = session.call(tool, args);
        REQUIRE(r.ok);
        CHECK(r.text.size() <= Session::maxResultBytes);
        const Json page = Json::parse(r.text);
        for (const auto& row : page["items"]) {
            rows.push_back(row);
        }
        if (page["next"].is_null()) {
            return rows;
        }
        args["cursor"] = page["next"];
    }
    FAIL("paging did not end");
    return rows;
}

} // namespace

TEST_CASE("Golden output for every tool, PE32+", "[tools][golden]") {
    runGolden(true);
}

TEST_CASE("Golden output for every tool, PE32", "[tools][golden]") {
    runGolden(false);
}

TEST_CASE("open_file, list_files and close_file", "[tools]") {
    synthetic::TempFile a(synthetic::build(true), "pemcp-a");
    synthetic::TempFile b(synthetic::build(false), "pemcp-b");
    Session session;

    CHECK(callErr(session, "headers") == "No file is open. Call open_file with a path first.");

    const Json first = callOk(session, "open_file", {{"path", a.utf8()}});
    CHECK(first["id"] == "f1");
    CHECK(first["format"] == "PE32+");
    CHECK(first["machine"] == "x64");
    const Json second = callOk(session, "open_file", {{"path", b.utf8()}});
    CHECK(second["id"] == "f2");
    CHECK(second["format"] == "PE32");

    // Opening the same file again returns its id rather than a second copy.
    const Json again = callOk(session, "open_file", {{"path", a.utf8()}});
    CHECK(again["id"] == "f1");
    CHECK(again["already_open"] == true);

    CHECK(callOk(session, "list_files")["files"].size() == 2);

    // With two files open, the file must be named.
    CHECK(callErr(session, "headers").find("Several files are open (f1, f2)") == 0);
    CHECK(callOk(session, "headers", {{"file", "f1"}})["image_base"] == "0x140000000");
    CHECK(callOk(session, "headers", {{"file", "f2"}})["image_base"] == "0x400000");
    CHECK(callErr(session, "headers", {{"file", "f9"}}).find("No open file has the id \"f9\"") == 0);

    CHECK(callOk(session, "close_file", {{"file", "f1"}})["closed"] == "f1");
    CHECK(callOk(session, "list_files")["files"].size() == 1);
    // One file left: file may be omitted again, and ids are not reused.
    CHECK(callOk(session, "headers")["format"] == "PE32");
    CHECK(callOk(session, "open_file", {{"path", a.utf8()}})["id"] == "f3");
}

TEST_CASE("Two builds can be compared side by side", "[tools]") {
    synthetic::TempFile a(synthetic::build(true), "pemcp-cmp");
    auto changed = synthetic::build(true);
    changed[0x404 + 7] ^= 0xFF; // one byte of .text differs
    synthetic::TempFile b(changed, "pemcp-cmp");
    Session session;
    REQUIRE(session.openAtStartup(a.path()).empty());
    REQUIRE(session.openAtStartup(b.path()).empty());
    const Json ha = callOk(session, "hash", {{"file", "f1"}});
    const Json hb = callOk(session, "hash", {{"file", "f2"}});
    CHECK(ha["sha256"] != hb["sha256"]);
    CHECK(ha["sections"][0]["sha256"] != hb["sections"][0]["sha256"]); // .text
    CHECK(ha["sections"][1]["sha256"] == hb["sections"][1]["sha256"]); // .rdata
    CHECK(ha["imphash"] == hb["imphash"]);
}

TEST_CASE("open_file reports a missing or non-PE file", "[tools]") {
    Session session;
    CHECK(callErr(session, "open_file", {{"path", "C:\\no\\such\\file.exe"}}).find("Cannot open the file") != std::string::npos);
    synthetic::TempFile text(std::vector<std::uint8_t>(100, 'x'), "pemcp-text");
    CHECK(callErr(session, "open_file", {{"path", text.utf8()}}).find("does not start with \"MZ\"") != std::string::npos);
    CHECK(callErr(session, "open_file", Json::object()) == "path is required.");
    CHECK(callErr(session, "open_file", {{"path", std::filesystem::temp_directory_path().string()}}).find("is a directory") !=
          std::string::npos);
    CHECK(session.openAtStartup("C:\\no\\such\\file.exe").size() > 0);
    CHECK(callOk(session, "list_files")["startup_errors"].size() == 1);
}

TEST_CASE("Arguments are checked, and a misspelled one is refused", "[tools]") {
    SyntheticSession s(true);
    auto& session = s.session;
    CHECK(callErr(session, "strings", {{"min_len", 4}}) ==
          "Unknown argument \"min_len\". strings takes: file, min_length, encoding, section, include_code, filter, limit, "
          "cursor.");
    CHECK(callErr(session, "disassemble", {{"rva", "0xZZ"}}) == "rva \"0xZZ\" is not a hex number.");
    CHECK(callErr(session, "disassemble", {{"rva", "0x1000"}, {"va", "0x140001000"}}) == "Pass rva or va, not both.");
    CHECK(callErr(session, "disassemble", Json::object()) == "Pass rva or va to say where to start.");
    CHECK(callErr(session, "disassemble", {{"va", "0x1000"}}).find("is not inside this image") != std::string::npos);
    CHECK(callErr(session, "strings", {{"min_length", 1}}) == "min_length must be from 2 to 200.");
    CHECK(callErr(session, "strings", {{"encoding", "utf8"}}) == "encoding must be \"ascii\", \"utf16\" or \"both\".");
    CHECK(callErr(session, "strings", {{"section", ".nope"}}).find("Sections: .text, .rdata, .data, .pdata, .rsrc.") !=
          std::string::npos);
    CHECK(callErr(session, "strings", {{"cursor", "abc"}}) == "cursor must be the `next` value from a previous page of this tool.");
    CHECK(callErr(session, "strings", {{"cursor", "99999"}}).find("past the end") != std::string::npos);
    CHECK(callErr(session, "xrefs_to", {{"include_data", "yes"}, {"rva", 1}}) == "include_data must be true or false.");
    CHECK(callErr(session, "find_pattern", {{"pattern", "48 8B 0"}}).find("The pattern could not be read") == 0);
    CHECK(callErr(session, "headers", Json::array()) == "arguments must be a JSON object.");
    // Addresses: integers are taken as is, strings as hex, with or without
    // 0x and with a WinDbg-style backtick.
    CHECK(callOk(session, "rva_to_offset", {{"rva", 4096}})["offset"] == "0x400");
    CHECK(callOk(session, "rva_to_offset", {{"rva", "1000"}})["offset"] == "0x400");
    CHECK(callOk(session, "rva_to_offset", {{"va", "00000001`40001000"}})["offset"] == "0x400");
    // Out-of-range limits are clamped, not refused.
    const Json all = callOk(session, "strings", {{"limit", 100000}});
    CHECK(all["items"].size() == all["total"].get<std::size_t>());
}

TEST_CASE("Addresses outside the file's data are explained", "[tools]") {
    SyntheticSession s(true);
    auto& session = s.session;
    CHECK(callErr(session, "rva_to_offset", {{"rva", "0x3800"}}) ==
          "RVA 0x3800 is in .data but past its file data; the loader zero-fills it, so it has no file offset.");
    CHECK(callErr(session, "rva_to_offset", {{"rva", "0x9000"}}) == "RVA 0x9000 is outside every section and past the headers.");
    CHECK(callErr(session, "offset_to_rva", {{"offset", "0x1000"}}).find("overlay") != std::string::npos);
    CHECK(callErr(session, "offset_to_rva", {{"offset", "0x100000"}}).find("past the end") != std::string::npos);
    CHECK(callErr(session, "read_bytes", {{"rva", "0x3800"}}).find("not backed by the file") != std::string::npos);
    CHECK(callOk(session, "offset_to_rva", {{"offset", "0x10"}})["section"] == "(headers)");
    // read_bytes stops at the end of the section's file data.
    const Json partial = callOk(session, "read_bytes", {{"rva", "0x31F8"}, {"length", 64}});
    CHECK(partial["requested"] == 64);
    CHECK(partial["length"] == 8);
    const Json overlay = callOk(session, "read_bytes", {{"offset", "0x1000"}, {"length", 16}});
    CHECK(overlay["hex"] == "4F5645524C41592D444154412D454E44"); // "OVERLAY-DATA-END"
    CHECK_FALSE(overlay.contains("rva"));
}

TEST_CASE("disassemble continues from its cursor", "[tools]") {
    SyntheticSession s(true);
    auto& session = s.session;
    const Json first = callOk(session, "disassemble", {{"rva", "0x1000"}, {"count", 3}});
    REQUIRE(first["items"].size() == 3);
    CHECK(first["next"] == "0x1011");
    const Json rest = callOk(session, "disassemble", {{"cursor", first["next"]}, {"count", 2}});
    CHECK(rest["items"][0]["rva"] == "0x1011");
    CHECK(rest["items"][1]["text"] == "call 0x140001040");
    CHECK(rest["items"][1]["note"] == "export fixture_add");
    // Function mode stops at the function's end and says there is no more.
    const Json fn = callOk(session, "disassemble", {{"rva", "0x1010"}, {"function", true}, {"count", 200}});
    CHECK(fn["function"]["begin"] == "0x1000");
    CHECK(fn["items"].size() == 8);
    CHECK(fn["next"].is_null());
    // Without a .pdata entry it says so and starts where it was asked to.
    const Json leaf = callOk(session, "disassemble", {{"rva", "0x1030"}, {"function", true}, {"count", 1}});
    CHECK(leaf["function"].is_null());
    CHECK(leaf["note"].get<std::string>().find("No .pdata entry covers this address") == 0);
    CHECK(leaf["items"][0]["rva"] == "0x1030");
}

TEST_CASE("Paging returns every row exactly once", "[tools][paging]") {
    synthetic::TempFile file(synthetic::buildManyStrings(3000), "pemcp-many");
    Session session;
    REQUIRE(session.openAtStartup(file.path()).empty());

    const Json first = callOk(session, "strings", {{"limit", 7}});
    CHECK(first["total"] == 3000);
    CHECK(first["items"].size() == 7);
    CHECK(first["next"] == "7");

    const auto rows = allPages(session, "strings", {{"limit", 250}});
    REQUIRE(rows.size() == 3000);
    std::set<std::string> seen;
    for (std::size_t i = 0; i < rows.size(); ++i) {
        char expected[32];
        std::snprintf(expected, sizeof(expected), "paging test string %05zu", i);
        CHECK(rows[i]["text"] == expected);
        seen.insert(rows[i]["rva"].get<std::string>());
    }
    CHECK(seen.size() == 3000);

    // The same holds for find_pattern, over its own list.
    const auto matches = allPages(session, "find_pattern", {{"pattern", "70 61 67 69 6E 67"}, {"limit", 1000}});
    CHECK(matches.size() == 3000);
}

TEST_CASE("A page never exceeds the size cap, whatever the limit", "[tools][paging]") {
    synthetic::TempFile file(synthetic::buildManyStrings(3000), "pemcp-cap");
    Session session;
    REQUIRE(session.openAtStartup(file.path()).empty());
    const auto r = session.call("strings", {{"limit", 1000}});
    REQUIRE(r.ok);
    CHECK(r.text.size() <= Session::maxResultBytes);
    const Json page = Json::parse(r.text);
    CHECK(page["items"].size() < 1000);
    CHECK(page["items"].size() > 100);
    CHECK(page["next"] == std::to_string(page["items"].size()));

    const auto bytes = session.call("read_bytes", {{"rva", "0x2000"}, {"length", 4096}});
    REQUIRE(bytes.ok);
    CHECK(bytes.text.size() <= Session::maxResultBytes);

    const auto code = session.call("disassemble", {{"rva", "0x2000"}, {"count", 200}});
    REQUIRE(code.ok);
    CHECK(code.text.size() <= Session::maxResultBytes);
}

TEST_CASE("Filters narrow the lists", "[tools]") {
    SyntheticSession s(true);
    auto& session = s.session;
    CHECK(callOk(session, "strings", {{"filter", "WIDE"}})["items"][0]["enc"] == "utf16");
    CHECK(callOk(session, "imports", {{"dll", "user32"}})["total"] == 1);
    CHECK(callOk(session, "imports", {{"filter", "tick"}})["items"][0]["name"] == "GetTickCount");
    CHECK(callOk(session, "exports", {{"filter", "forward"}})["items"][0]["forward"] == "KERNEL32.Sleep");
    CHECK(callOk(session, "resources", {{"type", "manifest"}})["total"] == 1);
    CHECK(callOk(session, "find_pattern", {{"pattern", "C3"}, {"section", ".rsrc"}})["total"] == 0);
    CHECK(callOk(session, "find_pattern", {{"pattern", "aobscanmodule(INJECT, fixture.exe, E8 ?? ?? ?? ?? 8B 05)"}})["total"] == 1);
    CHECK(callOk(session, "find_pattern", {{"pattern", "\"\\xE8\\x00\\x00\\x00\\x00\\x8B\" \"x????x\""}})["total"] == 1);
}

TEST_CASE("Every tool is listed with a schema", "[tools]") {
    Session session;
    std::set<std::string> names;
    for (const auto& t : session.tools()) {
        names.insert(t.name);
        CHECK(t.inputSchema["type"] == "object");
        CHECK(t.inputSchema["additionalProperties"] == false);
        CHECK_FALSE(t.description.empty());
    }
    CHECK(names == std::set<std::string>{"open_file", "close_file", "list_files", "headers", "sections", "imports", "exports",
                                         "strings", "disassemble", "xrefs_to", "find_pattern", "read_bytes", "hash",
                                         "rva_to_offset", "offset_to_rva", "tls_callbacks", "resources"});
}

TEST_CASE("strings skips code sections unless asked", "[tools]") {
    auto bytes = synthetic::build(true);
    const std::string text = "CODE SECTION STRING";
    std::copy(text.begin(), text.end(), bytes.begin() + 0x480); // .text padding, RVA 0x1080
    synthetic::TempFile file(bytes, "pemcp-code");
    Session session;
    REQUIRE(session.openAtStartup(file.path()).empty());
    CHECK(callOk(session, "strings", {{"filter", "code section"}})["total"] == 0);
    const Json withCode = callOk(session, "strings", {{"filter", "code section"}, {"include_code", true}});
    REQUIRE(withCode["total"] == 1);
    CHECK(withCode["items"][0]["rva"] == "0x1080");
    CHECK(callOk(session, "strings", {{"section", ".text"}})["total"] == 1);
}
