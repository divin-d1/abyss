#include "test_harness.h"

#include "crypto/sha256.h"

using namespace abyss;

ABYSS_TEST("sha256: matches known test vector for empty input") {
    std::string digest = crypto::sha256Hex(nullptr, 0);
    ABYSS_CHECK_EQ(digest, std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

ABYSS_TEST("sha256: matches known test vector for 'abc'") {
    const std::uint8_t data[] = {'a', 'b', 'c'};
    std::string digest = crypto::sha256Hex(data, 3);
    ABYSS_CHECK_EQ(digest, std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

ABYSS_TEST("sha256: is deterministic and sensitive to input changes") {
    const std::uint8_t a[] = {'x'};
    const std::uint8_t b[] = {'y'};
    ABYSS_CHECK_EQ(crypto::sha256Hex(a, 1), crypto::sha256Hex(a, 1));
    ABYSS_CHECK(crypto::sha256Hex(a, 1) != crypto::sha256Hex(b, 1));
}
