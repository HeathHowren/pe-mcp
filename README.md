<p align="center">
  <img src="docs/logo.svg" width="96" alt="pe-mcp logo">
</p>

# pe-mcp

An MCP server that gives an AI agent static analysis of Windows PE files.

[![CI](https://github.com/HeathHowren/pe-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/HeathHowren/pe-mcp/actions/workflows/ci.yml)

pe-mcp is a small Model Context Protocol server that reads an `.exe`, `.dll` or
`.sys` file from disk and answers questions about it: headers, sections,
imports, exports, strings, disassembly, cross-references, byte signatures,
hashes, TLS callbacks and resources. It never opens a process, attaches a
debugger or writes a byte. Every result is compact JSON with a hard size cap
and a cursor for the next page, because the output lands in a model's context
window. It speaks MCP over stdin and stdout, so registering it is one command
with no ports and no token.

pe-mcp is written by Heath Howren
([Cyborg Elf](https://www.youtube.com/cyborgelf)) of
[Game Reversal Club](https://gamereversal.club). It is the static half of
[Pointer Lab](https://github.com/HeathHowren/Pointer-Lab)'s MCP server: Pointer
Lab lets an agent work on a running program, and pe-mcp lets it read the file
first. Its `find_pattern` tool is [sigscan](https://github.com/HeathHowren/sigscan),
so a [Signature Lab](https://github.com/HeathHowren/Signature-Lab) signature can
be checked against a file before the program is even running.

```
# server pe-mcp 1.0.0, 17 tools
> strings {"filter":"Health: %.3f"}
{
  "total": 1,
  "items": [
    {"rva":"0x1B518","enc":"utf16","text":"Health: %.3f     Ammo: %.4f"}
  ],
  "next": null
}
> xrefs_to {"rva":"0x1B518"}
{
  "target": "0x1B518",
  "note": "L\"Health: %.3f     Ammo: %.4f\"",
  "total": 1,
  "items": [
    {"rva":"0x1B4B","kind":"rip","text":"lea r8, [0x14001B518]","function":"0x1B40"}
  ],
  "next": null
}
> disassemble {"rva":"0x1B4B","function":true}
{
  "function": {"begin":"0x1B40","end":"0x1B79"},
  "items": [
    {"rva":"0x1B40","bytes":"4883EC38","text":"sub rsp, 0x38"},
    {"rva":"0x1B44","bytes":"488B057DC00200","text":"mov rax, [0x14002DBC8]","ref":"0x2DBC8"},
    {"rva":"0x1B4B","bytes":"4C8D05C6990100","text":"lea r8, [0x14001B518]","ref":"0x1B518","note":"L\"Health: %.3f     Ammo: %.4f\""},
    {"rva":"0x1B52","bytes":"F30F1000","text":"movss xmm0, dword ptr [rax]"},
    {"rva":"0x1B56","bytes":"488B0573C00200","text":"mov rax, [0x14002DBD0]","ref":"0x2DBD0"},
    {"rva":"0x1B5D","bytes":"0F5AD8","text":"cvtps2pd xmm3, xmm0"},
    {"rva":"0x1B60","bytes":"F20F1008","text":"movsd xmm1, qword ptr [rax]"},
    {"rva":"0x1B64","bytes":"66490F7ED9","text":"movq r9, xmm3"},
    {"rva":"0x1B69","bytes":"F20F114C2420","text":"movsd [rsp+0x20], xmm1"},
    {"rva":"0x1B6F","bytes":"E83C1F0000","text":"call 0x140003AB0","ref":"0x3AB0"},
    {"rva":"0x1B74","bytes":"4883C438","text":"add rsp, 0x38"},
    {"rva":"0x1B78","bytes":"C3","text":"ret"}
  ],
  "next": null
}
```

*Real output. A small scripted MCP client spoke to `pe-mcp.exe` over stdio,
the way Claude Code does, against a local build of the Pointer Lab tutorial
(`PointerLabTutorial.exe`). It found the health text, the one instruction that
uses it, and the function around that instruction, which reads the float health
and the double ammo through two globals. The client printed one row per line;
the rows are as the server sent them.*

## What it does

- **Reads the whole PE.** Headers with mitigations (ASLR, DEP, CFG) and the
  PDB path, sections with entropy, imports with their IAT slots (delay-loaded
  ones too), exports with forwarders, TLS callbacks, and the resource tree.
  PE32 and PE32+.
- **Finds strings.** ASCII and UTF-16LE, with a minimum length, a section
  filter and a text filter. Each string comes with its RVA, ready for
  `xrefs_to`.
- **Disassembles x86 and x64 code** with [Zydis](https://github.com/zyantific/zydis).
  An instruction that points into the image carries the target RVA and a note
  naming the import, export or string there. On x64, `function: true` uses
  `.pdata` to disassemble the whole function around an address.
- **Finds cross-references.** It decodes every executable section and reports
  each relative call or jump, RIP-relative operand and absolute address that
  points at an RVA or a range. On x64 each hit names its function. Optionally
  it also finds pointers in data sections, such as vtable entries.
- **Tests signatures.** `find_pattern` takes a signature in any form sigscan
  reads (x64dbg, IDA, code and mask, C++ array, `aobscanmodule(...)`) and
  returns every match with its RVA, file offset and section, plus the total.
- **Hashes.** SHA-256 of the file and of each section, and the imphash.
- **Keeps several files open.** Each has a short id (`f1`, `f2`), so an agent
  can compare two builds.
- **Sizes every answer for a model.** Lists are paged with `limit`, `cursor`
  and `next`. No result is larger than 24 KB of JSON, whatever the limit.
- **Reports damage instead of crashing.** Every read is bounds-checked. A
  truncated or corrupt file is refused with the reason, or read in part with
  warnings about what could not be read.

## What it does not do

- It does not touch a running process. For that, use Pointer Lab's MCP server.
- It does not load PDB symbols, parse .NET metadata or disassemble ARM64 code.
  The headers and tables of an ARM64 file still read.
- Cross-references come from a linear sweep. Data inside a code section can
  hide the instruction after it, and a call through a register or a computed
  address is not a reference it can see.
- Function bounds come from `.pdata`, so they exist only on x64, and not for a
  function that never touches the stack. `disassemble` says so and starts at
  the address it was given.
- `strings` scans section data, not the headers or the overlay, and skips
  executable sections unless asked, because code reads as short junk strings.
- The imphash spells every ordinal import as `ordN`. pefile names ordinal
  imports from `ws2_32`, `wsock32` and `oleaut32` from a table, so those three
  hash differently.
- Files are read whole into memory, up to 1 GiB each and 16 at once.
- There is no HTTP transport in 1.0. stdio is what `claude mcp add` and most
  clients use, and it needs no port and no token.

## Download

Get the latest zip from
[Releases](https://github.com/HeathHowren/pe-mcp/releases). It contains:

```
pe-mcp.exe
LICENSE, README.md, CHANGELOG.md, THIRD_PARTY_NOTICES.md
```

There is an x64 and an x86 zip. Either build reads both PE32 and PE32+ files;
use the x64 one unless you are on 32-bit Windows. The C runtime is linked
statically, so nothing else needs to be installed.

The binary is unsigned. pe-mcp only reads files, but build from source if you
would rather not take a binary on trust.

## Quick start

Register it with Claude Code, naming the file to analyze:

```
claude mcp add pe-mcp -- C:\Tools\pe-mcp\pe-mcp.exe C:\Games\MyGame\game.exe
```

Files named on the command line are opened at startup as `f1`, `f2` and so on.
You can also leave them off and let the agent call `open_file` with a path.
Then ask Claude Code something like "find the function that draws the health
text" and it will call the tools.

Any other MCP client that can launch a stdio server takes the same command and
arguments. In a JSON config that is usually:

```json
{
  "mcpServers": {
    "pe-mcp": {
      "command": "C:\\Tools\\pe-mcp\\pe-mcp.exe",
      "args": ["C:\\Games\\MyGame\\game.exe"]
    }
  }
}
```

`pe-mcp --help` prints the usage. Anything that is not a protocol message goes
to stderr, never stdout.

## Tools

| Tool | What it returns |
|---|---|
| `open_file` | Opens a file by path and returns its id. Opening an open file returns the same id. |
| `close_file` | Closes a file by id. |
| `list_files` | The open files, and any file from the command line that failed to open, with the reason. |
| `headers` | Format, machine, timestamp, image base, entry point, subsystem, characteristics, mitigations, data directories, PDB path, overlay. |
| `sections` | Name, RVA, virtual size, file offset, raw size, `r/w/x` flags and entropy. |
| `imports` | DLL, function name or ordinal, and IAT slot RVA. `dll` and `filter` narrow it. The first page also lists the DLLs with a count each. |
| `exports` | Ordinal, name, and RVA or forwarder. |
| `strings` | RVA, encoding and text. `min_length`, `encoding`, `section`, `include_code`, `filter`. |
| `disassemble` | Instructions from an `rva` or `va`: RVA, bytes, text, and `ref`/`note` for targets in the image. `count` up to 200; `function` for the whole function (x64). |
| `xrefs_to` | Every instruction referring to an `rva` or `va` (or a `size`-byte range): RVA, kind, text and, on x64, function. `include_data` adds data pointers. |
| `find_pattern` | Every match of a signature: RVA, file offset and section, and the total. |
| `read_bytes` | Up to 4096 bytes as hex, by `rva`, `va` or `offset`. |
| `hash` | SHA-256 of the file and each section, and the imphash. |
| `rva_to_offset` | File offset and section of an `rva` or `va`, or why it has none. |
| `offset_to_rva` | RVA, VA and section of a file offset, or why it has none. |
| `tls_callbacks` | The TLS directory and each callback's VA, RVA and section. |
| `resources` | Type, name, language, RVA and size of each resource. `type` narrows it. |

Every tool is marked read-only in `tools/list`, and each one's input schema
describes its arguments.

### Conventions

- **Files.** Pass `file` with an id such as `"f1"`. It may be left out when
  exactly one file is open.
- **Addresses** are RVAs unless a tool says otherwise. `disassemble`,
  `xrefs_to`, `read_bytes` and `rva_to_offset` also take `va`. In a result,
  every address and offset is a hex string such as `"0x1B518"`. As an
  argument, a string is always read as hex (`"0x1B518"`, `"1B518"` and
  WinDbg's ``"00000001`4001B518"`` all work) and an integer is taken as is.
- **Paging.** A list result has `total`, `items` and `next`. Pass `next` back
  as `cursor`, with the same arguments, for the next page. `next` is `null` on
  the last page. `limit` sets the rows per page; a page also stops early
  rather than go over 24 KB. For `disassemble`, `next` is the RVA to continue
  from.
- **Errors.** A bad argument or an unusable file comes back as a normal tool
  result with `isError` set and a sentence saying what was wrong, so the model
  can correct itself. A misspelled argument name is refused with the list of
  names the tool takes, rather than silently ignored. JSON-RPC errors are kept
  for protocol mistakes: bad JSON (`-32700`), a malformed request (`-32600`),
  an unknown method (`-32601`), and a missing or unknown tool name (`-32602`).
- **Transport.** One JSON-RPC 2.0 message per line on stdin and stdout, as the
  MCP stdio transport specifies. It answers `initialize`, `ping`, `tools/list`
  and `tools/call`, and ignores notifications. It speaks protocol revisions
  2025-06-18, 2025-03-26 and 2024-11-05.

## Build

Requirements: Visual Studio 2022 with the C++ workload and CMake 3.28 or newer.
The CMake that ships with Visual Studio is recent enough.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

For the 32-bit build, configure a second tree with `-A Win32`. The first
configure downloads Zydis and Catch2, pinned by commit and tag, and the
nlohmann/json header, pinned by SHA-256. sigscan is vendored in
`third_party/sigscan`. To produce the release zip:

```powershell
cpack --config build/CPackConfig.cmake -C Release -B build/package
```

The tests build a PE32+ and a PE32 file byte by byte, so every RVA in them is
known, and compare each tool's output with the golden files in `tests/golden`.
They also cover paging and the size cap, truncated files and random header
mutations, the JSON-RPC layer, and an end-to-end run that starts
`pe-mcp.exe`, speaks MCP to it over pipes, and follows a string to its
function in a small compiled fixture program.

## Intended use

pe-mcp is for studying software **you own or are authorized to analyze**: your
own programs, single-player games, CTF binaries, and the lab targets from
[*The Game Hacker's Handbook*](https://gamereversal.club/books/game-hackers-handbook/). It reads files and changes nothing, but what you do with what it
finds is your decision.

## License

MIT; see [LICENSE](LICENSE). pe-mcp statically links Zydis and Zycore and
includes nlohmann/json and sigscan, all MIT. The tests use Catch2 (Boost
Software License 1.0), which does not ship in the zip. Details are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
