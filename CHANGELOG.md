# Changelog

All notable changes to pe-mcp are recorded here. This project follows
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-09-26

The first release.

### Added

- **An MCP server over stdio.** JSON-RPC 2.0, one message per line, with
  `initialize`, `ping`, `tools/list` and `tools/call`. Register it with
  `claude mcp add pe-mcp -- pe-mcp.exe [file ...]`; files named on the command
  line open at startup.
- **Seventeen read-only tools.** `open_file`, `close_file`, `list_files`,
  `headers`, `sections`, `imports`, `exports`, `strings`, `disassemble`,
  `xrefs_to`, `find_pattern`, `read_bytes`, `hash`, `rva_to_offset`,
  `offset_to_rva`, `tls_callbacks` and `resources`. PE32 and PE32+.
- **Several files open at once**, each with a short id, so two builds can be
  compared.
- **Results sized for a model's context.** Compact JSON, hex-string addresses,
  paging with `limit`, `cursor` and `next`, and a 24 KB ceiling on any one
  result.
- **Disassembly with notes.** x86 and x64 through Zydis 4.1.1. An instruction
  that points into the image carries the target RVA and the import, export or
  string there. On x64, `function: true` disassembles the whole function from
  `.pdata`, following chained unwind info to the primary entry.
- **Cross-references by linear sweep.** Relative calls and jumps,
  RIP-relative operands and absolute addresses, to an RVA or a range, with the
  containing function on x64, and optionally pointers in data sections.
- **Signature search through sigscan**, in every form it parses, with the
  total match count so a signature can be checked for uniqueness.
- **Hashes.** SHA-256 of the file and each section, and the imphash.
- **Careful with bad input.** Every read is bounds-checked. A truncated or
  corrupt file is refused with the reason or read in part with warnings;
  corrupt counts and loops in the import, export, TLS and resource tables are
  capped. A misspelled argument name is refused, not ignored.
- **Tests.** Golden outputs for every tool against a PE32+ and a PE32 built
  byte by byte, paging and size caps, truncation and random mutation of the
  headers, the JSON-RPC layer, and an end-to-end run of `pe-mcp.exe` over
  pipes against a compiled fixture program.
