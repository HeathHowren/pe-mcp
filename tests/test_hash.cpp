#include "SyntheticPe.h"
#include "pe/Hash.h"
#include "pe/PeFile.h"

#include <catch2/catch_test_macros.hpp>

#include <string>

using namespace pemcp;

namespace {

std::span<const std::uint8_t> bytesOf(const std::string& s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

} // namespace

TEST_CASE("SHA-256 matches the FIPS 180-4 test vectors", "[hash]") {
    CHECK(sha256Hex(bytesOf("")) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(sha256Hex(bytesOf("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(sha256Hex(bytesOf("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")) ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    CHECK(sha256Hex(bytesOf(std::string(1000000, 'a'))) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST_CASE("SHA-256 and MD5 pad correctly around the block boundary", "[hash]") {
    // Lengths either side of 56 and 64 bytes, where the length field does and
    // does not fit in the last block. Expected values from coreutils.
    struct Case {
        std::size_t n;
        const char* sha;
        const char* md5;
    };
    const Case cases[] = {
        {55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318", "ef1772b6dff9a122358552954ad0df65"},
        {56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a", "3b0c8ac703f828b04c6c197006d17218"},
        {63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34", "b06521f39153d618550606be297466d5"},
        {64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb", "014842d480b571495a4a0363793f7367"},
        {65, "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0", "c743a45e0d2e6a95cb859adae0248435"},
        {119, "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb", "8a7bd0732ed6a28ce75f6dabc90e1613"},
        {120, "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c", "5f61c0ccad4cac44c75ff505e1f1e537"},
    };
    for (const Case& c : cases) {
        const std::string input(c.n, 'a');
        INFO("length " << c.n);
        CHECK(sha256Hex(bytesOf(input)) == c.sha);
        CHECK(md5Hex(bytesOf(input)) == c.md5);
    }
}

TEST_CASE("MD5 matches the RFC 1321 test vectors", "[hash]") {
    CHECK(md5Hex(bytesOf("")) == "d41d8cd98f00b204e9800998ecf8427e");
    CHECK(md5Hex(bytesOf("abc")) == "900150983cd24fb0d6963f7d28e17f72");
    CHECK(md5Hex(bytesOf("message digest")) == "f96b697d7cb7938d525a2f31aaf161d0");
    CHECK(md5Hex(bytesOf("12345678901234567890123456789012345678901234567890123456789012345678901234567890")) ==
          "57edf4a22be3c955ac49da2e2107b67a");
}

TEST_CASE("imphash follows pefile's normalization", "[hash]") {
    for (bool is64 : {true, false}) {
        std::string error;
        const auto pe = PeFile::parse(synthetic::build(is64), error);
        REQUIRE(pe);
        // Lowercased, extension dropped, ordinal spelled ordN, table order.
        CHECK(imphashInput(*pe) == "kernel32.outputdebugstringa,kernel32.gettickcount,user32.ord7");
        CHECK(imphash(*pe) == "71b054fb35998db09bc90ccf6561fda2");
    }
}
