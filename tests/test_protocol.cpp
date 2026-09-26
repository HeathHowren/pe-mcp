#include "TestSupport.h"
#include "mcp/Protocol.h"

#include <catch2/catch_test_macros.hpp>

using namespace testing;
using pemcp::mcp::Server;

namespace {

Json send(Server& server, const std::string& message) {
    const std::string reply = server.handle(message);
    INFO(message << " -> " << reply);
    REQUIRE_FALSE(reply.empty());
    CHECK(reply.find('\n') == std::string::npos); // one line per message
    return Json::parse(reply);
}

int errorCode(const Json& reply) {
    REQUIRE(reply.contains("error"));
    return reply["error"]["code"].get<int>();
}

} // namespace

TEST_CASE("initialize negotiates the protocol version", "[protocol]") {
    Session session;
    Server server(session);
    Json r = send(server, R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26",)"
                          R"("capabilities":{},"clientInfo":{"name":"test","version":"1"}}})");
    CHECK(r["id"] == 1);
    CHECK(r["result"]["protocolVersion"] == "2025-03-26");
    CHECK(r["result"]["serverInfo"]["name"] == "pe-mcp");
    CHECK(r["result"]["serverInfo"]["version"] == PEMCP_VERSION);
    CHECK(r["result"]["capabilities"]["tools"]["listChanged"] == false);
    CHECK_FALSE(r["result"]["instructions"].get<std::string>().empty());

    // A version it does not know is answered with the newest it does.
    r = send(server, R"({"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"1999-01-01"}})");
    CHECK(r["id"] == "a");
    CHECK(r["result"]["protocolVersion"] == "2025-06-18");
}

TEST_CASE("Notifications get no reply", "[protocol]") {
    Session session;
    Server server(session);
    CHECK(server.handle(R"({"jsonrpc":"2.0","method":"notifications/initialized"})").empty());
    CHECK(server.handle(R"({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":3}})").empty());
    CHECK(server.handle(R"({"jsonrpc":"2.0","method":"no/such/thing"})").empty());
    // A response from the client, to a request the server never made.
    CHECK(server.handle(R"({"jsonrpc":"2.0","id":9,"result":{}})").empty());
}

TEST_CASE("Protocol errors carry the JSON-RPC codes", "[protocol]") {
    Session session;
    Server server(session);
    Json r = send(server, "{not json");
    CHECK(errorCode(r) == pemcp::mcp::errParse);
    CHECK(r["id"].is_null());

    CHECK(errorCode(send(server, "42")) == pemcp::mcp::errInvalidRequest);
    CHECK(errorCode(send(server, "[]")) == pemcp::mcp::errInvalidRequest);
    CHECK(errorCode(send(server, R"({"jsonrpc":"2.0","id":1})")) == pemcp::mcp::errInvalidRequest);
    CHECK(errorCode(send(server, R"({"jsonrpc":"1.0","id":1,"method":"ping"})")) == pemcp::mcp::errInvalidRequest);
    CHECK(errorCode(send(server, R"({"id":1,"method":"ping"})")) == pemcp::mcp::errInvalidRequest);
    CHECK(errorCode(send(server, R"({"jsonrpc":"2.0","id":{"x":1},"method":"ping"})")) == pemcp::mcp::errInvalidRequest);
    CHECK(errorCode(send(server, R"({"jsonrpc":"2.0","id":1,"method":7})")) == pemcp::mcp::errInvalidRequest);

    r = send(server, R"({"jsonrpc":"2.0","id":2,"method":"resources/read"})");
    CHECK(errorCode(r) == pemcp::mcp::errMethodNotFound);
    CHECK(r["id"] == 2);
    CHECK(r["error"]["message"] == "There is no method called \"resources/read\".");

    CHECK(errorCode(send(server, R"({"jsonrpc":"2.0","id":3,"method":"tools/call"})")) == pemcp::mcp::errInvalidParams);
    CHECK(errorCode(send(server, R"({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{}})")) == pemcp::mcp::errInvalidParams);
    CHECK(errorCode(send(server, R"({"jsonrpc":"2.0","id":5,"method":"tools/call","params":[1]})")) == pemcp::mcp::errInvalidParams);
    r = send(server, R"({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"delete_everything"}})");
    CHECK(errorCode(r) == pemcp::mcp::errInvalidParams);
    CHECK(r["error"]["message"] == "There is no tool called \"delete_everything\". tools/list names them.");
}

TEST_CASE("ping and tools/list", "[protocol]") {
    Session session;
    Server server(session);
    CHECK(send(server, R"({"jsonrpc":"2.0","id":1,"method":"ping"})")["result"] == Json::object());
    const Json r = send(server, R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})");
    const Json& tools = r["result"]["tools"];
    CHECK(tools.size() == 17);
    for (const auto& t : tools) {
        CHECK(t.contains("name"));
        CHECK(t.contains("description"));
        CHECK(t["inputSchema"]["type"] == "object");
        CHECK(t["annotations"]["readOnlyHint"] == true);
    }
}

TEST_CASE("tools/call returns text content, and tool failures as isError", "[protocol]") {
    SyntheticSession s(true);
    Server server(s.session);
    Json r = send(server, R"({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"exports","arguments":{}}})");
    CHECK(r["id"] == 7);
    CHECK(r["result"]["isError"] == false);
    REQUIRE(r["result"]["content"].size() == 1);
    CHECK(r["result"]["content"][0]["type"] == "text");
    const Json inner = Json::parse(r["result"]["content"][0]["text"].get<std::string>());
    CHECK(inner["items"][0]["name"] == "fixture_add");

    // arguments may be left out entirely.
    r = send(server, R"({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"list_files"}})");
    CHECK(r["result"]["isError"] == false);

    // A bad argument is the tool's error, for the model to read.
    r = send(server, R"({"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read_bytes","arguments":{"rva":"zz"}}})");
    CHECK(r["result"]["isError"] == true);
    CHECK(r["result"]["content"][0]["text"] == "rva \"zz\" is not a hex number.");
}

TEST_CASE("A batch is answered as a batch, without the notifications", "[protocol]") {
    Session session;
    Server server(session);
    const Json r = send(server, R"([{"jsonrpc":"2.0","id":1,"method":"ping"},)"
                                R"({"jsonrpc":"2.0","method":"notifications/initialized"},)"
                                R"({"jsonrpc":"2.0","id":2,"method":"nope"}])");
    REQUIRE(r.is_array());
    REQUIRE(r.size() == 2);
    CHECK(r[0]["id"] == 1);
    CHECK(r[1]["error"]["code"] == pemcp::mcp::errMethodNotFound);
    CHECK(server.handle(R"([{"jsonrpc":"2.0","method":"notifications/initialized"}])").empty());
}

TEST_CASE("Text that is not UTF-8 is replaced, not thrown on", "[protocol]") {
    // Names read out of a binary, and Windows error text, can be any bytes.
    CHECK(pemcp::mcp::dumpCompact(Json("bad \xFF byte")) == "\"bad \xEF\xBF\xBD byte\"");

    // A non-ASCII path survives the trip into the error sentence.
    SyntheticSession s(true);
    Server server(s.session);
    const std::string request = R"({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"open_file",)"
                                R"("arguments":{"path":"C:\\missing-\u00e9.exe"}}})";
    const Json r = send(server, request);
    CHECK(r["result"]["isError"] == true);
    CHECK(r["result"]["content"][0]["text"].get<std::string>().find("missing-\xC3\xA9.exe") != std::string::npos);
}

