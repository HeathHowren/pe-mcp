#pragma once

// JSON-RPC 2.0 and the MCP methods on top of it: initialize, ping, tools/list
// and tools/call.
//
// One message in, one message out, as strings. The stdio loop in main.cpp
// feeds it lines; the tests feed it strings directly. Nothing here reads or
// writes a stream.

#include "mcp/Tools.h"

#include <string>
#include <string_view>

namespace pemcp::mcp {

// The protocol revisions this server speaks, newest first. A client asking for
// one of these gets it back; a client asking for anything else is offered the
// newest, which is what the MCP lifecycle specifies.
inline constexpr const char* supportedProtocolVersions[] = {"2025-06-18", "2025-03-26", "2024-11-05"};

// JSON-RPC error codes.
inline constexpr int errParse = -32700;
inline constexpr int errInvalidRequest = -32600;
inline constexpr int errMethodNotFound = -32601;
inline constexpr int errInvalidParams = -32602;
inline constexpr int errInternal = -32603;

class Server {
public:
    explicit Server(Session& session) : session_(session) {}

    // Handles one message. Returns the response as a single line of JSON with
    // no trailing newline, or an empty string when there is nothing to send:
    // a notification is never answered, not even with an error.
    [[nodiscard]] std::string handle(std::string_view message);

private:
    [[nodiscard]] Json respond(const Json& message);
    [[nodiscard]] Json initialize(const Json& params) const;
    [[nodiscard]] Json toolsList() const;

    Session& session_;
};

} // namespace pemcp::mcp
