#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace abyss::crypto {

// SHA-256 over a byte buffer, computed via Windows CNG (BCrypt). Returns a
// lowercase hex digest, or an empty string on failure (e.g. BCrypt provider
// unavailable). No third-party crypto library is used.
std::string sha256Hex(const std::uint8_t* data, std::size_t len);
std::string sha256Hex(const std::vector<std::uint8_t>& data);

} // namespace abyss::crypto
