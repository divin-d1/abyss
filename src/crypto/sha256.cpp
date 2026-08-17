#include "crypto/sha256.h"

#include "core/core.h"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif
#endif

namespace abyss::crypto {

#if defined(_WIN32)

std::string sha256Hex(const std::uint8_t* data, std::size_t len) {
    BCRYPT_ALG_HANDLE algHandle = nullptr;
    BCRYPT_HASH_HANDLE hashHandle = nullptr;
    std::string result;

    if (BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        return result;
    }

    DWORD hashObjectSize = 0, cbData = 0;
    if (BCryptGetProperty(algHandle, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hashObjectSize,
                           sizeof(hashObjectSize), &cbData, 0) != 0) {
        BCryptCloseAlgorithmProvider(algHandle, 0);
        return result;
    }

    DWORD hashLen = 0;
    if (BCryptGetProperty(algHandle, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen),
                           &cbData, 0) != 0) {
        BCryptCloseAlgorithmProvider(algHandle, 0);
        return result;
    }

    std::vector<std::uint8_t> hashObject(hashObjectSize);
    std::vector<std::uint8_t> hash(hashLen);

    if (BCryptCreateHash(algHandle, &hashHandle, hashObject.data(), hashObjectSize, nullptr, 0,
                          0) != 0) {
        BCryptCloseAlgorithmProvider(algHandle, 0);
        return result;
    }

    NTSTATUS status = BCryptHashData(hashHandle, (PUCHAR)const_cast<std::uint8_t*>(data),
                                      (ULONG)len, 0);
    if (status == 0) {
        status = BCryptFinishHash(hashHandle, hash.data(), hashLen, 0);
        if (status == 0) {
            result = abyss::toHex(hash.data(), hash.size());
        }
    }

    BCryptDestroyHash(hashHandle);
    BCryptCloseAlgorithmProvider(algHandle, 0);
    return result;
}

#else

// Small portable SHA-256 fallback used by tests and source builds on
// non-Windows hosts. Windows releases use the OS CNG implementation above.
namespace {
constexpr std::uint32_t rotr(std::uint32_t v, unsigned n) { return (v >> n) | (v << (32 - n)); }

constexpr std::uint32_t k[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};
}

std::string sha256Hex(const std::uint8_t* data, std::size_t len) {
    std::vector<std::uint8_t> message;
    message.reserve(len + 72);
    if (len != 0 && data != nullptr) message.insert(message.end(), data, data + len);
    message.push_back(0x80);
    while ((message.size() % 64) != 56) message.push_back(0);
    const std::uint64_t bitLen = static_cast<std::uint64_t>(len) * 8u;
    for (int shift = 56; shift >= 0; shift -= 8) message.push_back(static_cast<std::uint8_t>(bitLen >> shift));

    std::uint32_t h[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                          0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    for (std::size_t offset = 0; offset < message.size(); offset += 64) {
        std::uint32_t w[64]{};
        for (int i = 0; i < 16; ++i) {
            const std::size_t p = offset + static_cast<std::size_t>(i) * 4;
            w[i] = (static_cast<std::uint32_t>(message[p]) << 24) |
                   (static_cast<std::uint32_t>(message[p + 1]) << 16) |
                   (static_cast<std::uint32_t>(message[p + 2]) << 8) |
                   static_cast<std::uint32_t>(message[p + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const auto s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
            const auto s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        std::uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            const auto s1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
            const auto ch = (e & f) ^ ((~e) & g);
            const auto t1 = hh + s1 + ch + k[i] + w[i];
            const auto s0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
            const auto maj = (a & b) ^ (a & c) ^ (b & c);
            const auto t2 = s0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }
    std::uint8_t digest[32];
    for (int i = 0; i < 8; ++i) {
        digest[i*4] = static_cast<std::uint8_t>(h[i] >> 24);
        digest[i*4+1] = static_cast<std::uint8_t>(h[i] >> 16);
        digest[i*4+2] = static_cast<std::uint8_t>(h[i] >> 8);
        digest[i*4+3] = static_cast<std::uint8_t>(h[i]);
    }
    return abyss::toHex(digest, sizeof(digest));
}

#endif

std::string sha256Hex(const std::vector<std::uint8_t>& data) {
    return sha256Hex(data.data(), data.size());
}

} // namespace abyss::crypto
