#pragma once

// SHA-256 and MD5, written out so the core has no dependency on a platform
// crypto API. MD5 is here only because imphash is defined as an MD5; nothing
// in pe-mcp uses it for security.

#include <cstdint>
#include <span>
#include <string>

namespace pemcp {

class PeFile;

[[nodiscard]] std::string sha256Hex(std::span<const std::uint8_t> data);
[[nodiscard]] std::string md5Hex(std::span<const std::uint8_t> data);

// The import hash as pefile and VirusTotal define it: the MD5 of
// "dll.function" pairs, lowercased, comma-joined, in table order, with the
// .dll/.ocx/.sys extension dropped. Imports by ordinal are spelled "ordN".
// pefile names ordinal imports from ws2_32, wsock32 and oleaut32 from a lookup
// table; pe-mcp does not, so a file importing those by ordinal hashes
// differently. Returns an empty string when there are no imports.
[[nodiscard]] std::string imphash(const PeFile& pe);
[[nodiscard]] std::string imphashInput(const PeFile& pe);

} // namespace pemcp
