#pragma once

// The tools, and the table of open files they work on.
//
// A Session knows nothing about JSON-RPC or stdio. It takes a tool name and an
// arguments object and returns either compact JSON or a sentence saying what
// was wrong, which is all the protocol layer and the tests need.

#include <nlohmann/json.hpp>

#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace pemcp::mcp {

using Json = nlohmann::ordered_json;

struct ToolSpec {
    std::string name;
    std::string description;
    Json inputSchema;
};

struct CallResult {
    bool ok = false;
    std::string text; // compact JSON on success, a sentence on failure
};

// JSON for output: compact, and never throws on a byte sequence that is not
// UTF-8 (it is replaced), because text read out of a binary can be anything.
[[nodiscard]] std::string dumpCompact(const Json& value);

class Session {
public:
    Session();
    ~Session();
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // The ceiling on one tool result, in bytes of JSON. Lists stop early and
    // hand back a `next` cursor rather than go over it.
    static constexpr std::size_t maxResultBytes = 24 * 1024;
    static constexpr std::size_t maxOpenFiles = 16;

    [[nodiscard]] const std::vector<ToolSpec>& tools() const;
    [[nodiscard]] bool hasTool(const std::string& name) const;

    // Runs a tool. Never throws: a bad argument, a malformed file or an
    // internal failure all come back as ok == false with a sentence.
    [[nodiscard]] CallResult call(const std::string& name, const Json& arguments);

    // Opens a file given on the command line. Returns the error sentence, or
    // an empty string on success. A failure is also listed by list_files.
    std::string openAtStartup(const std::filesystem::path& path);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace pemcp::mcp
