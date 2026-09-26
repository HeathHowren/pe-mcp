#pragma once

#include "SyntheticPe.h"
#include "mcp/Tools.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

namespace testing {

using pemcp::mcp::Json;
using pemcp::mcp::Session;

// Calls a tool that must succeed and returns its parsed result.
inline Json callOk(Session& session, const std::string& tool, const Json& args = Json::object()) {
    const auto r = session.call(tool, args);
    INFO(tool << " " << pemcp::mcp::dumpCompact(args) << " -> " << r.text);
    REQUIRE(r.ok);
    return Json::parse(r.text);
}

// Calls a tool that must fail and returns its error sentence.
inline std::string callErr(Session& session, const std::string& tool, const Json& args = Json::object()) {
    const auto r = session.call(tool, args);
    INFO(tool << " " << pemcp::mcp::dumpCompact(args) << " -> " << r.text);
    REQUIRE_FALSE(r.ok);
    REQUIRE_FALSE(r.text.empty());
    return r.text;
}

// A session with the synthetic PE open as f1.
struct SyntheticSession {
    synthetic::TempFile file;
    Session session;
    explicit SyntheticSession(bool is64) : file(synthetic::build(is64), is64 ? "pemcp-x64" : "pemcp-x86") {
        REQUIRE(session.openAtStartup(file.path()).empty());
    }
};

inline std::string readText(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    std::string s = ss.str();
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) {
        s.pop_back();
    }
    return s;
}

// Compares a tool's output with tests/golden/<name>.json. With
// PEMCP_UPDATE_GOLDEN=1 in the environment the file is rewritten instead,
// and the diff is reviewed in version control.
inline void checkGolden(const std::string& name, const std::string& actual) {
    const std::filesystem::path path = std::filesystem::path(PEMCP_GOLDEN_DIR) / (name + ".json");
    char* update = nullptr;
    std::size_t len = 0;
    const bool rewrite = _dupenv_s(&update, &len, "PEMCP_UPDATE_GOLDEN") == 0 && update != nullptr && update[0] == '1';
    std::free(update);
    if (rewrite) {
        std::filesystem::create_directories(path.parent_path());
        std::ofstream out(path, std::ios::binary);
        out << actual << "\n";
        return;
    }
    INFO("golden file " << path.string());
    REQUIRE(std::filesystem::exists(path));
    CHECK(readText(path) == actual);
}

} // namespace testing
