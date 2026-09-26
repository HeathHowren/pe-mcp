#include "mcp/Protocol.h"

#include <exception>

namespace pemcp::mcp {

namespace {

constexpr const char* instructions =
    "Static analysis of Windows PE files on disk. Read-only: no process is touched and nothing is written. "
    "Open a file with open_file (or use one given on the command line; list_files shows them), then address it by its "
    "id. Addresses are RVAs unless a tool says otherwise; every address in a result is a hex string. Lists are paged: "
    "pass a result's next value back as cursor for more. A typical path from a string to the code that uses it: "
    "strings with filter, then xrefs_to on the string's rva, then disassemble with function true at the referencing "
    "instruction.";

Json error(const Json& id, int code, const std::string& message) {
    return {{"jsonrpc", "2.0"}, {"id", id}, {"error", {{"code", code}, {"message", message}}}};
}

Json result(const Json& id, Json value) {
    return {{"jsonrpc", "2.0"}, {"id", id}, {"result", std::move(value)}};
}

} // namespace

std::string Server::handle(std::string_view message) {
    Json parsed;
    try {
        parsed = Json::parse(message);
    } catch (const std::exception&) {
        return dumpCompact(error(nullptr, errParse, "The message is not valid JSON."));
    }

    if (parsed.is_array()) {
        // Batches were removed from MCP in 2025-06-18, but answering one costs
        // nothing and a client that sends one should not be left hanging.
        if (parsed.empty()) {
            return dumpCompact(error(nullptr, errInvalidRequest, "An empty batch is not a request."));
        }
        Json responses = Json::array();
        for (const Json& m : parsed) {
            Json r = respond(m);
            if (!r.is_null()) {
                responses.push_back(std::move(r));
            }
        }
        return responses.empty() ? std::string() : dumpCompact(responses);
    }

    const Json r = respond(parsed);
    return r.is_null() ? std::string() : dumpCompact(r);
}

Json Server::respond(const Json& message) {
    if (!message.is_object()) {
        return error(nullptr, errInvalidRequest, "A message must be a JSON object.");
    }
    const bool hasId = message.contains("id");
    const Json id = hasId ? message.at("id") : Json(nullptr);
    if (hasId && !id.is_string() && !id.is_number_integer() && !id.is_null()) {
        return error(nullptr, errInvalidRequest, "id must be a string or an integer.");
    }
    // Responses the client sends us (to requests we never make) and
    // notifications both get silence.
    if (!message.contains("method")) {
        if (message.contains("result") || message.contains("error")) {
            return nullptr;
        }
        return hasId ? error(id, errInvalidRequest, "The request has no method.") : Json(nullptr);
    }
    const bool notification = !hasId;
    if (!message.at("method").is_string()) {
        return notification ? Json(nullptr) : error(id, errInvalidRequest, "method must be a string.");
    }
    if (!message.contains("jsonrpc") || message.at("jsonrpc") != "2.0") {
        return notification ? Json(nullptr) : error(id, errInvalidRequest, "jsonrpc must be \"2.0\".");
    }
    const std::string method = message.at("method").get<std::string>();
    const Json params = message.contains("params") ? message.at("params") : Json(nullptr);
    if (!params.is_null() && !params.is_object()) {
        return notification ? Json(nullptr) : error(id, errInvalidParams, "params must be an object.");
    }

    if (notification) {
        // notifications/initialized, notifications/cancelled and anything
        // else: there is no state here that a notification changes.
        return nullptr;
    }

    try {
        if (method == "initialize") {
            return result(id, initialize(params));
        }
        if (method == "ping") {
            return result(id, Json::object());
        }
        if (method == "tools/list") {
            return result(id, toolsList());
        }
        if (method == "tools/call") {
            if (params.is_null() || !params.contains("name") || !params.at("name").is_string()) {
                return error(id, errInvalidParams, "tools/call needs params.name, the tool to call.");
            }
            const std::string name = params.at("name").get<std::string>();
            if (!session_.hasTool(name)) {
                return error(id, errInvalidParams, "There is no tool called \"" + name + "\". tools/list names them.");
            }
            const Json arguments = params.contains("arguments") ? params.at("arguments") : Json::object();
            // A tool's own failure is a successful response with isError set,
            // so the model sees the sentence and can act on it. JSON-RPC errors
            // are for protocol mistakes, which are the client's to fix.
            const CallResult r = session_.call(name, arguments);
            return result(id, {{"content", Json::array({{{"type", "text"}, {"text", r.text}}})}, {"isError", !r.ok}});
        }
    } catch (const std::exception& e) {
        return error(id, errInternal, std::string("Internal error: ") + e.what());
    }
    return error(id, errMethodNotFound, "There is no method called \"" + method + "\".");
}

Json Server::initialize(const Json& params) const {
    std::string version = supportedProtocolVersions[0];
    if (params.is_object() && params.contains("protocolVersion") && params.at("protocolVersion").is_string()) {
        const auto asked = params.at("protocolVersion").get<std::string>();
        for (const char* v : supportedProtocolVersions) {
            if (asked == v) {
                version = asked;
            }
        }
    }
    return {{"protocolVersion", version},
            {"capabilities", {{"tools", {{"listChanged", false}}}}},
            {"serverInfo", {{"name", "pe-mcp"}, {"title", "pe-mcp"}, {"version", PEMCP_VERSION}}},
            {"instructions", instructions}};
}

Json Server::toolsList() const {
    Json tools = Json::array();
    for (const ToolSpec& t : session_.tools()) {
        tools.push_back({{"name", t.name},
                         {"description", t.description},
                         {"inputSchema", t.inputSchema},
                         {"annotations", {{"readOnlyHint", true}, {"openWorldHint", false}}}});
    }
    return {{"tools", std::move(tools)}};
}

} // namespace pemcp::mcp
