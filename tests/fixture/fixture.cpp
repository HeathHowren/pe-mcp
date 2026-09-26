// The end-to-end fixture: a small real program for pe-mcp to analyze.
//
// What the tests look for in it:
//   - the string "pe-mcp fixture: find me by xref", used by exactly one
//     function, report_health, so strings -> xrefs_to -> disassemble lands
//     there;
//   - an export, pe_mcp_fixture_add;
//   - imports of GetTickCount and OutputDebugStringA from KERNEL32;
//   - a TLS callback;
//   - an RCDATA resource (fixture.rc).
//
// It is never run by the tests, only read.

#include <windows.h>

#include <cstdio>

extern "C" __declspec(dllexport) int pe_mcp_fixture_add(int a, int b) {
    return a + b;
}

static void NTAPI fixture_on_tls(PVOID, DWORD, PVOID) {
    OutputDebugStringA("pe-mcp fixture: TLS callback");
}

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:fixture_tls_callback")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_fixture_tls_callback")
#endif
#pragma section(".CRT$XLB", read)
extern "C" __declspec(allocate(".CRT$XLB")) const PIMAGE_TLS_CALLBACK fixture_tls_callback = fixture_on_tls;

__declspec(noinline) static void report_health(int health) {
    std::printf("pe-mcp fixture: find me by xref (health %d)\n", health);
}

int main() {
    report_health(pe_mcp_fixture_add(static_cast<int>(GetTickCount() & 1), 99));
    return 0;
}
