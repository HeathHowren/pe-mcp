#include "pe/Hash.h"

#include "pe/Bytes.h"
#include "pe/PeFile.h"

#include <array>
#include <cstring>

namespace pemcp {

namespace {

constexpr std::uint32_t rotr(std::uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}
constexpr std::uint32_t rotl(std::uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

std::string toHex(const std::uint8_t* digest, std::size_t n) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    for (std::size_t i = 0; i < n; ++i) {
        out += digits[digest[i] >> 4];
        out += digits[digest[i] & 0xF];
    }
    return out;
}

// Both hashes pad the same way: 0x80, zeros, then the bit length in eight
// bytes, big-endian for SHA-256 and little-endian for MD5.
std::array<std::uint8_t, 128> finalBlocks(const std::uint8_t* tail, std::size_t tailLen, std::uint64_t totalLen, bool bigEndian,
                                          std::size_t& blocks) {
    std::array<std::uint8_t, 128> buf{};
    std::memcpy(buf.data(), tail, tailLen);
    buf[tailLen] = 0x80;
    blocks = tailLen + 9 <= 64 ? 1 : 2;
    const std::uint64_t bits = totalLen * 8;
    std::uint8_t* len = buf.data() + blocks * 64 - 8;
    for (int i = 0; i < 8; ++i) {
        len[bigEndian ? 7 - i : i] = static_cast<std::uint8_t>(bits >> (8 * i));
    }
    return buf;
}

// --- SHA-256 (FIPS 180-4) ---

constexpr std::uint32_t k256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
    0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
    0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void sha256Block(std::uint32_t h[8], const std::uint8_t* p) {
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (std::uint32_t{p[4 * i]} << 24) | (std::uint32_t{p[4 * i + 1]} << 16) | (std::uint32_t{p[4 * i + 2]} << 8) | p[4 * i + 3];
    }
    for (int i = 16; i < 64; ++i) {
        const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
        const std::uint32_t t1 = hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + k256[i] + w[i];
        const std::uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

// --- MD5 (RFC 1321) ---

constexpr std::uint32_t kMd5[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1,
    0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453,
    0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942,
    0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
    0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};
constexpr int sMd5[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                          4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

void md5Block(std::uint32_t h[4], const std::uint8_t* p) {
    std::uint32_t m[16];
    for (int i = 0; i < 16; ++i) {
        m[i] = std::uint32_t{p[4 * i]} | (std::uint32_t{p[4 * i + 1]} << 8) | (std::uint32_t{p[4 * i + 2]} << 16) |
               (std::uint32_t{p[4 * i + 3]} << 24);
    }
    std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
    for (int i = 0; i < 64; ++i) {
        std::uint32_t f;
        int g;
        if (i < 16) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | (~d & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | ~d);
            g = (7 * i) % 16;
        }
        const std::uint32_t tmp = d;
        d = c;
        c = b;
        b = b + rotl(a + f + kMd5[i] + m[g], sMd5[i]);
        a = tmp;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
}

} // namespace

std::string sha256Hex(std::span<const std::uint8_t> data) {
    std::uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    const std::size_t whole = data.size() / 64;
    for (std::size_t i = 0; i < whole; ++i) {
        sha256Block(h, data.data() + i * 64);
    }
    std::size_t blocks = 0;
    const auto tail = finalBlocks(data.data() + whole * 64, data.size() % 64, data.size(), true, blocks);
    for (std::size_t i = 0; i < blocks; ++i) {
        sha256Block(h, tail.data() + i * 64);
    }
    std::uint8_t digest[32];
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 4; ++j) {
            digest[4 * i + j] = static_cast<std::uint8_t>(h[i] >> (24 - 8 * j));
        }
    }
    return toHex(digest, 32);
}

std::string md5Hex(std::span<const std::uint8_t> data) {
    std::uint32_t h[4] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    const std::size_t whole = data.size() / 64;
    for (std::size_t i = 0; i < whole; ++i) {
        md5Block(h, data.data() + i * 64);
    }
    std::size_t blocks = 0;
    const auto tail = finalBlocks(data.data() + whole * 64, data.size() % 64, data.size(), false, blocks);
    for (std::size_t i = 0; i < blocks; ++i) {
        md5Block(h, tail.data() + i * 64);
    }
    std::uint8_t digest[16];
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            digest[4 * i + j] = static_cast<std::uint8_t>(h[i] >> (8 * j));
        }
    }
    return toHex(digest, 16);
}

std::string imphashInput(const PeFile& pe) {
    std::string out;
    for (const Import& imp : pe.imports().imports) {
        if (imp.delay) {
            continue; // pefile hashes the regular import table only
        }
        std::string lib;
        for (char c : imp.dll) {
            lib += static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
        }
        const auto dot = lib.rfind('.');
        if (dot != std::string::npos) {
            const std::string ext = lib.substr(dot + 1);
            if (ext == "dll" || ext == "ocx" || ext == "sys") {
                lib.resize(dot);
            }
        }
        std::string fn = imp.byOrdinal ? "ord" + std::to_string(imp.ordinal) : imp.name;
        for (char& c : fn) {
            c = static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
        }
        if (!out.empty()) {
            out += ',';
        }
        out += lib + "." + fn;
    }
    return out;
}

std::string imphash(const PeFile& pe) {
    const std::string input = imphashInput(pe);
    if (input.empty()) {
        return {};
    }
    return md5Hex(std::span(reinterpret_cast<const std::uint8_t*>(input.data()), input.size()));
}

} // namespace pemcp
