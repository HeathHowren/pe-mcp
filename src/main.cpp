// pe-mcp: an MCP server over PE files, on stdin and stdout.
//
// The stdio transport is one JSON-RPC message per line in each direction.
// Nothing but protocol messages may be written to stdout, so everything a
// person might want to read goes to stderr.

#include "mcp/Protocol.h"
#include "mcp/Tools.h"

#include <cstdio>
#include <fcntl.h>
#include <io.h>
#include <iostream>
#include <string>

namespace {

void usage() {
    std::fputs("pe-mcp " PEMCP_VERSION ": an MCP server for static analysis of PE files.\n"
               "\n"
               "Usage: pe-mcp [file ...]\n"
               "\n"
               "Speaks MCP (JSON-RPC 2.0) on stdin and stdout, one message per line. Files\n"
               "named on the command line are opened at startup as f1, f2, ...\n"
               "\n"
               "Register it with Claude Code:\n"
               "  claude mcp add pe-mcp -- C:\\path\\to\\pe-mcp.exe C:\\path\\to\\game.exe\n",
               stderr);
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    pemcp::mcp::Session session;
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
            usage();
            return 0;
        }
        if (arg == L"--version") {
            std::fputs("pe-mcp " PEMCP_VERSION "\n", stderr);
            return 0;
        }
        // A file that will not open is reported, not fatal: an MCP client
        // shows a server that exits at startup only as "failed to connect",
        // and list_files carries the reason to the agent instead.
        const std::string error = session.openAtStartup(arg);
        if (!error.empty()) {
            std::fprintf(stderr, "pe-mcp: %s\n", error.c_str());
        }
    }

    // Binary mode: a CRLF on the way out would be harmless to most clients,
    // but the transport says a newline ends a message, and a stray CR inside
    // the stream is not ours to add.
    (void)_setmode(_fileno(stdin), _O_BINARY);
    (void)_setmode(_fileno(stdout), _O_BINARY);

    pemcp::mcp::Server server(session);
    std::string line;
    while (std::getline(std::cin, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.find_first_not_of(" \t") == std::string::npos) {
            continue;
        }
        const std::string response = server.handle(line);
        if (response.empty()) {
            continue;
        }
        std::cout << response << '\n';
        std::cout.flush();
        if (!std::cout) {
            return 1; // the client has gone
        }
    }
    return 0;
}
