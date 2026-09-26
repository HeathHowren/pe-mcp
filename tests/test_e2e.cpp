// End to end: start pe-mcp.exe on the compiled fixture, speak MCP to it over
// pipes the way Claude Code does, and follow a string to the function that
// uses it.

#include "TestSupport.h"
#include "mcp/Protocol.h"

#include <catch2/catch_test_macros.hpp>

#include <windows.h>

#include <chrono>
#include <string>

using namespace testing;

namespace {

class ServerProcess {
public:
    explicit ServerProcess(const std::wstring& arguments) {
        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
        HANDLE childIn = nullptr;
        HANDLE childOut = nullptr;
        REQUIRE(CreatePipe(&childIn, &toChild_, &sa, 0));
        REQUIRE(CreatePipe(&fromChild_, &childOut, &sa, 0));
        SetHandleInformation(toChild_, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(fromChild_, HANDLE_FLAG_INHERIT, 0);
        nul_ = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = childIn;
        si.hStdOutput = childOut;
        si.hStdError = nul_;
        std::wstring command = L"\"" + std::filesystem::path(PEMCP_SERVER_EXE).wstring() + L"\" " + arguments;
        PROCESS_INFORMATION pi{};
        const BOOL ok = CreateProcessW(nullptr, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        CloseHandle(childIn);
        CloseHandle(childOut);
        REQUIRE(ok);
        process_ = pi.hProcess;
        CloseHandle(pi.hThread);
    }

    ~ServerProcess() {
        closeInput();
        if (process_) {
            if (WaitForSingleObject(process_, 5000) != WAIT_OBJECT_0) {
                TerminateProcess(process_, 1);
            }
            CloseHandle(process_);
        }
        CloseHandle(fromChild_);
        if (nul_ != INVALID_HANDLE_VALUE) {
            CloseHandle(nul_);
        }
    }

    void sendLine(const std::string& line) {
        const std::string framed = line + "\n";
        DWORD written = 0;
        REQUIRE(WriteFile(toChild_, framed.data(), static_cast<DWORD>(framed.size()), &written, nullptr));
        REQUIRE(written == framed.size());
    }

    // Reads one newline-terminated message, with a deadline so a hung server
    // fails the test instead of hanging it.
    std::string readLine() {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        for (;;) {
            if (const auto nl = buffer_.find('\n'); nl != std::string::npos) {
                std::string line = buffer_.substr(0, nl);
                buffer_.erase(0, nl + 1);
                return line;
            }
            DWORD available = 0;
            REQUIRE(PeekNamedPipe(fromChild_, nullptr, 0, nullptr, &available, nullptr));
            if (available == 0) {
                REQUIRE(std::chrono::steady_clock::now() < deadline);
                Sleep(5);
                continue;
            }
            char chunk[65536];
            DWORD read = 0;
            REQUIRE(ReadFile(fromChild_, chunk, std::min<DWORD>(available, sizeof(chunk)), &read, nullptr));
            buffer_.append(chunk, read);
        }
    }

    Json request(int id, const std::string& method, const Json& params) {
        sendLine(pemcp::mcp::dumpCompact({{"jsonrpc", "2.0"}, {"id", id}, {"method", method}, {"params", params}}));
        const Json reply = Json::parse(readLine());
        REQUIRE(reply["id"] == id);
        return reply;
    }

    // tools/call, returning the tool's own JSON.
    Json tool(int id, const std::string& name, const Json& arguments) {
        const Json reply = request(id, "tools/call", {{"name", name}, {"arguments", arguments}});
        INFO(name << " -> " << pemcp::mcp::dumpCompact(reply));
        REQUIRE(reply["result"]["isError"] == false);
        return Json::parse(reply["result"]["content"][0]["text"].get<std::string>());
    }

    void closeInput() {
        if (toChild_) {
            CloseHandle(toChild_);
            toChild_ = nullptr;
        }
    }

    DWORD waitForExit() {
        REQUIRE(WaitForSingleObject(process_, 10000) == WAIT_OBJECT_0);
        DWORD code = 0;
        GetExitCodeProcess(process_, &code);
        return code;
    }

private:
    HANDLE toChild_ = nullptr;
    HANDLE fromChild_ = nullptr;
    HANDLE process_ = nullptr;
    HANDLE nul_ = INVALID_HANDLE_VALUE;
    std::string buffer_;
};

} // namespace

TEST_CASE("End to end over stdio: from a string to the function that uses it", "[e2e]") {
    ServerProcess server(L"\"" + std::filesystem::path(PEMCP_FIXTURE_EXE).wstring() + L"\"");

    const Json init = server.request(1, "initialize",
                                     {{"protocolVersion", "2025-06-18"},
                                      {"capabilities", Json::object()},
                                      {"clientInfo", {{"name", "pemcp-e2e"}, {"version", "1"}}}});
    CHECK(init["result"]["serverInfo"]["name"] == "pe-mcp");
    server.sendLine(R"({"jsonrpc":"2.0","method":"notifications/initialized"})");
    CHECK(server.request(2, "tools/list", Json::object())["result"]["tools"].size() == 17);

    const Json files = server.tool(3, "list_files", Json::object());
    REQUIRE(files["files"].size() == 1);
    // The fixture is built for the same architecture as the tests.
    CHECK(files["files"][0]["format"] == (sizeof(void*) == 8 ? "PE32+" : "PE32"));
    CHECK(files["files"][0]["machine"] == (sizeof(void*) == 8 ? "x64" : "x86"));

    // 1. Find the string.
    const Json strings = server.tool(4, "strings", {{"filter", "find me by xref"}});
    REQUIRE(strings["items"].size() == 1);
    const std::string stringRva = strings["items"][0]["rva"];

    // 2. Find the code that uses it: exactly one instruction, in report_health.
    const Json xrefs = server.tool(5, "xrefs_to", {{"rva", stringRva}});
    REQUIRE(xrefs["total"] == 1);
    const std::string user = xrefs["items"][0]["rva"];
    CHECK(xrefs.value("note", "").find("find me by xref") != std::string::npos);

    // 3. Disassemble the function. On x64 its bounds come from .pdata when it
    // has an entry; an optimizer may make report_health frameless, and then
    // it has none and the listing starts at the reference.
    const Json code = server.tool(6, "disassemble", {{"rva", user}, {"function", true}, {"count", 12}});
    if (xrefs["items"][0].contains("function")) {
        CHECK(xrefs["items"][0]["function"] == code["function"]["begin"]);
    } else {
        CHECK(code["function"].is_null());
    }
    bool sawString = false;
    bool sawCall = false;
    for (const auto& row : code["items"]) {
        if (row.contains("ref") && row["ref"] == stringRva) {
            sawString = true;
            CHECK(row.value("note", "").find("find me by xref") != std::string::npos);
        }
        const std::string text = row["text"];
        if (text.rfind("call", 0) == 0 || text.rfind("jmp", 0) == 0) {
            sawCall = true; // to printf, or a tail jump to it
        }
    }
    CHECK(sawString);
    CHECK(sawCall);

    // The rest of the fixture's known content.
    const Json exports = server.tool(7, "exports", Json::object());
    REQUIRE(exports["total"] == 1);
    CHECK(exports["items"][0]["name"] == "pe_mcp_fixture_add");
    const Json imports = server.tool(8, "imports", {{"filter", "GetTickCount"}});
    REQUIRE(imports["total"] == 1);
    CHECK(imports["items"][0]["dll"] == "KERNEL32.dll");
    const Json callers = server.tool(9, "xrefs_to", {{"rva", imports["items"][0]["iat"]}});
    CHECK(callers["total"].get<int>() >= 1);
    CHECK(callers.value("note", "") == "KERNEL32.dll!GetTickCount");
    const Json tls = server.tool(10, "tls_callbacks", Json::object());
    REQUIRE(tls["callbacks"].size() >= 1);
    CHECK(tls["callbacks"][0]["section"] == ".text");
    const Json rsrc = server.tool(11, "resources", {{"type", "RCDATA"}});
    REQUIRE(rsrc["total"] == 1);
    CHECK(rsrc["items"][0]["name"] == "#101");

    // Closing stdin ends the session cleanly.
    server.closeInput();
    CHECK(server.waitForExit() == 0);
}

TEST_CASE("End to end: a bad file on the command line does not stop the server", "[e2e]") {
    ServerProcess server(L"C:\\no\\such\\file.exe");
    const Json files = server.tool(1, "list_files", Json::object());
    CHECK(files["files"].empty());
    REQUIRE(files["startup_errors"].size() == 1);
    // Garbage on the wire gets a parse error and the server carries on.
    server.sendLine("this is not json");
    const Json err = Json::parse(server.readLine());
    CHECK(err["error"]["code"] == pemcp::mcp::errParse);
    CHECK(server.request(2, "ping", Json::object())["result"] == Json::object());
}
