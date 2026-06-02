#ifndef LOFER_PERMUTATION_HPP
#define LOFER_PERMUTATION_HPP

#include "types.hpp"
#include "prng.hpp"
#include <cstdint>
#include <numeric>

namespace lofer {

/**
 * @brief Compute modular multiplicative inverse using extended Euclidean algorithm
 * @param a Value to find inverse for
 * @param m Modulus
 * @return Inverse of a mod m, or 0 if no inverse exists
 */
inline size_t modInverse(size_t a, size_t m) noexcept {
    if (m == 0) return 0;
    
    int32_t m0 = static_cast<int32_t>(m);
    int32_t aa = static_cast<int32_t>(a % m);
    int32_t y = 0, x = 1;
    
    if (aa == 0) return 0;
    if (aa == 1) return 1;
    
    int32_t mm = m0;
    while (aa > 1 && mm > 0) {
        int32_t q = aa / mm;
        int32_t t = mm;
        mm = aa % mm;
        aa = t;
        t = y;
        y = x - q * y;
        x = t;
    }
    
    if (x < 0) x += m0;
    return static_cast<size_t>(x);
}

/**
 * @brief Generate bijective substitution table using Fisher-Yates shuffle
 * @param roundSeed Seed data for PRNG
 * @return Bijective S-box mapping
 */
inline std::array<Element, M> generateSubstitutionTable(const std::array<Byte, 32>& roundSeed) {
    PRNG prng;
    prng.seed(std::vector<Byte>(roundSeed.begin(), roundSeed.end()));
    
    // Create identity permutation
    std::array<Element, M> S;
    for (size_t i = 0; i < M; ++i) {
        S[i] = static_cast<Element>(i);
    }
    
    // Fisher-Yates shuffle (modern version: iterate forward)
    for (size_t i = M - 1; i > 0; --i) {
        size_t j = prng.nextBounded(static_cast<uint32_t>(i + 1));
        Element tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
    
    return S;
}

/**
 * @brief Generate inverse substitution table
 * @param S Forward substitution table
 * @return Inverse substitution table
 */
inline std::array<Element, M> generateInverseSubstitutionTable(const std::array<Element, M>& S) {
    std::array<Element, M> invS;
    for (size_t x = 0; x < M; ++x) {
        invS[S[x]] = static_cast<Element>(x);
    }
    return invS;
}

/**
 * @brief Generate affine permutation parameters
 * @param prngSeed Seed for PRNG
 * @param L Data length
 * @param a Output: multiplier (coprime with L)
 * @param b Output: offset
 */
inline void generatePermutation(const std::array<Byte, 32>& prngSeed, size_t L, 
                                 size_t& a, size_t& b) {
    PRNG prng;
    prng.seed(std::vector<Byte>(prngSeed.begin(), prngSeed.end()));
    
    // Find 'a' coprime with L
    do {
        a = prng.nextBounded(static_cast<uint32_t>(L));
        if (a == 0) a = 1;
        // Ensure gcd(a, L) == 1
        uint32_t aa_val = static_cast<uint32_t>(a);
        uint32_t ll = static_cast<uint32_t>(L);
        while (ll) {
            uint32_t t = ll;
            ll = aa_val % ll;
            aa_val = t;
        }
        if (aa_val == 1) break;
    } while (true);
    
    b = prng.nextBounded(static_cast<uint32_t>(L));
}

/**
 * @brief Initialize all round parameters for encryption/decryption
 * @param password User password
 * @param salt Salt value
 * @param R Output: number of rounds
 * @param params Output: round parameters
 * @param config Cipher configuration (optional, uses defaults if not provided)
 */
inline void deriveParameters(const std::string& password, 
                              const std::array<Byte, SALT_LEN>& salt,
                              int& R, 
                              std::vector<RoundParams>& params,
                              const CipherConfig& config = CipherConfig()) {
    // Convert salt to vector for KDF
    std::vector<Byte> saltVec(salt.begin(), salt.end());
    
    // Derive master key using PBKDF2-HMAC
    size_t masterKeyLen = 64 + HMAC_LEN;  // 64 bytes for cipher + 32 bytes for HMAC key
    
    std::vector<Byte> masterKey;
    if (config.hashAlgo == HashAlgorithm::SHA512) {
        masterKey = PBKDF2::derive<SHA512>(password, saltVec, config.pbkdf2Iterations, masterKeyLen);
    } else {
        masterKey = PBKDF2::derive<SHA256>(password, saltVec, config.pbkdf2Iterations, masterKeyLen);
    }
    
    // Use configured number of rounds (or derive from key material if not specified)
    if (config.numRounds > 0) {
        R = config.numRounds;
    } else {
        R = R_MIN + (masterKey[0] % (R_MAX - R_MIN + 1));
    }
    
    params.resize(R);
    
    // Expand key for per-round seeds using simpler derivation
    std::vector<Byte> expandedKey;
    expandedKey.reserve(R * 64);
    
    // Generate expanded key by hashing master key with counter
    for (int r = 0; r < R; ++r) {
        std::vector<Byte> seedData = masterKey;
        seedData.push_back(static_cast<Byte>(r & 0xFF));
        seedData.push_back(static_cast<Byte>((r >> 8) & 0xFF));
        
        std::array<Byte, 64> blockHash;
        if (config.hashAlgo == HashAlgorithm::SHA512) {
            auto hash512 = SHA512::hash(seedData);
            std::memcpy(blockHash.data(), hash512.data(), 64);
        } else {
            auto hash256 = SHA256::hash(seedData);
            std::memcpy(blockHash.data(), hash256.data(), 32);
            std::memset(blockHash.data() + 32, 0, 32);
        }
        expandedKey.insert(expandedKey.end(), blockHash.begin(), blockHash.end());
    }
    
    for (int r = 0; r < R; ++r) {
        // Get round seed from expanded key
        std::array<Byte, 32> roundSeed;
        std::memcpy(roundSeed.data(), expandedKey.data() + r * 64, 32);
        
        // Generate S-box and its inverse
        params[r].S_r = generateSubstitutionTable(roundSeed);
        params[r].invS_r = generateInverseSubstitutionTable(params[r].S_r);
        
        // Generate PRNG seed for permutation
        std::memcpy(params[r].prngSeed.data(), expandedKey.data() + r * 64 + 32, 32);
    }
    
    // Clear sensitive data
    secureZero(masterKey);
    secureZero(expandedKey);
}

/**
 * @brief Instantiate permutation parameters for specific data length
 * @param L Data length
 * @param params Round parameters (updated in place)
 */
inline void instantiatePermutations(size_t L, std::vector<RoundParams>& params) {
    for (auto& p : params) {
        // Generate permutation parameters
        generatePermutation(p.prngSeed, L, p.a, p.b);
        
        // Compute inverse parameters
        if (L > 1) {
            p.a_inv = modInverse(p.a, L);
            p.b_inv = (L - (p.a_inv * p.b) % L) % L;
        } else {
            p.a_inv = 0;
            p.b_inv = 0;
        }
    }
}

} // namespace lofer

#endif // LOFER_PERMUTATION_HPP
