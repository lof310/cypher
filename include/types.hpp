#ifndef LOFER_TYPES_HPP
#define LOFER_TYPES_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include <string>

// Compiler optimization hints
#if defined(__GNUC__) || defined(__clang__)
    #define LOFER_LIKELY(x)   __builtin_expect(!!(x), 1)
    #define LOFER_UNLIKELY(x) __builtin_expect(!!(x), 0)
    #define LOFER_HOT         __attribute__((hot))
    #define LOFER_COLD        __attribute__((cold))
    #define LOFER_FORCEINLINE __attribute__((always_inline)) inline
    #define LOFER_NOINLINE    __attribute__((noinline))
    #define LOFER_RESTRICT    __restrict__
#elif defined(_MSC_VER)
    #define LOFER_LIKELY(x)   (x)
    #define LOFER_UNLIKELY(x) (x)
    #define LOFER_HOT
    #define LOFER_COLD        __declspec(noinline)
    #define LOFER_FORCEINLINE __forceinline
    #define LOFER_NOINLINE    __declspec(noinline)
    #define LOFER_RESTRICT    __restrict
#else
    #define LOFER_LIKELY(x)   (x)
    #define LOFER_UNLIKELY(x) (x)
    #define LOFER_HOT
    #define LOFER_COLD
    #define LOFER_FORCEINLINE inline
    #define LOFER_NOINLINE
    #define LOFER_RESTRICT
#endif

namespace lofer {

// Algorithm Parameters - cache line aligned
constexpr size_t SALT_LEN = 16;
constexpr int R_MIN = 8;
constexpr int R_MAX = 32;
constexpr size_t M = 256;  // Alphabet size (2^8 for bytes)
constexpr size_t CACHE_LINE_SIZE = 64;
constexpr size_t HMAC_LEN = 32;  // HMAC-SHA256 output length
constexpr size_t SHA256_LEN = 32;
constexpr size_t SHA512_LEN = 64;
constexpr uint32_t DEFAULT_PBKDF2_ITERATIONS = 100000;

using Element = uint8_t;
using Byte = uint8_t;

/**
 * @brief Hash algorithm selection
 */
enum class HashAlgorithm {
    SHA256,
    SHA512
};

/**
 * @brief Configuration options for the cipher
 */
struct CipherConfig {
    HashAlgorithm hashAlgo = HashAlgorithm::SHA256;  // Hash function to use
    uint32_t pbkdf2Iterations = DEFAULT_PBKDF2_ITERATIONS;  // PBKDF2 iterations
    int numRounds = 16;  // Number of SPN rounds (8-32)
    bool useAuthentication = true;  // Enable HMAC authentication
    
    // Validate configuration
    bool isValid() const noexcept {
        return numRounds >= R_MIN && numRounds <= R_MAX &&
               pbkdf2Iterations >= 10000;  // Minimum reasonable iterations
    }
};

// Round parameters structure - optimized for cache locality
struct alignas(CACHE_LINE_SIZE) RoundParams {
    std::array<Element, M> S_r;           // Substitution table (S-box)
    std::array<Element, M> invS_r;        // Inverse substitution table
    size_t a, b;                          // Affine permutation parameters
    size_t a_inv, b_inv;                  // Inverse affine parameters
    std::array<Byte, 32> prngSeed;        // PRNG seed for this round
};

// Cipher context holding all derived parameters
struct CipherContext {
    int R;                                          // Number of rounds
    std::vector<RoundParams> params;                // Round parameters
    std::array<Byte, SALT_LEN> salt;               // Salt used in encryption
    std::array<Byte, 32> hmacKey;                  // Key for HMAC authentication
    CipherConfig config;                           // Configuration used
};

} // namespace lofer

#endif // LOFER_TYPES_HPP
