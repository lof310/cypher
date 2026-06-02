#ifndef LOFER_KDF_HPP
#define LOFER_KDF_HPP

#include "types.hpp"
#include <vector>
#include <string>
#include <cstdint>
#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace lofer {

/**
 * @brief SHA-256 cryptographic hash function
 * 
 * Implements FIPS 180-4 compliant SHA-256
 */
class SHA256 {
public:
    static constexpr size_t BLOCK_SIZE = 64;
    static constexpr size_t HASH_SIZE = 32;
    
    SHA256() { reset(); }
    
    void reset() {
        h[0] = 0x6a09e667; h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372; h[3] = 0xa54ff53a;
        h[4] = 0x510e527f; h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab; h[7] = 0x5be0cd19;
        bitCount = 0;
        bufferPos = 0;
    }
    
    void update(const Byte* data, size_t len) {
        while (len > 0) {
            size_t copy = std::min(len, BLOCK_SIZE - bufferPos);
            std::memcpy(buffer + bufferPos, data, copy);
            bufferPos += copy;
            data += copy;
            len -= copy;
            
            if (bufferPos == BLOCK_SIZE) {
                processBlock(buffer);
                bufferPos = 0;
            }
        }
    }
    
    void update(const std::vector<Byte>& data) {
        update(data.data(), data.size());
    }
    
    std::array<Byte, HASH_SIZE> finalize() {
        // Padding
        uint64_t totalBits = bitCount + bufferPos * 8;
        buffer[bufferPos++] = 0x80;
        
        // Pad to 56 bytes mod 64
        while (bufferPos != 56) {
            if (bufferPos == BLOCK_SIZE) {
                processBlock(buffer);
                bufferPos = 0;
            }
            buffer[bufferPos++] = 0x00;
        }
        
        // Append bit count (big-endian)
        for (int i = 7; i >= 0; --i) {
            buffer[bufferPos++] = static_cast<Byte>((totalBits >> (i * 8)) & 0xFF);
        }
        
        processBlock(buffer);
        
        // Output hash (big-endian)
        std::array<Byte, HASH_SIZE> result;
        for (int i = 0; i < 8; ++i) {
            result[i * 4 + 0] = static_cast<Byte>((h[i] >> 24) & 0xFF);
            result[i * 4 + 1] = static_cast<Byte>((h[i] >> 16) & 0xFF);
            result[i * 4 + 2] = static_cast<Byte>((h[i] >> 8) & 0xFF);
            result[i * 4 + 3] = static_cast<Byte>(h[i] & 0xFF);
        }
        
        reset();
        return result;
    }
    
    static std::array<Byte, HASH_SIZE> hash(const std::vector<Byte>& data) {
        SHA256 ctx;
        ctx.update(data);
        return ctx.finalize();
    }
    
    static std::array<Byte, HASH_SIZE> hash(const Byte* data, size_t len) {
        SHA256 ctx;
        ctx.update(data, len);
        return ctx.finalize();
    }

private:
    uint32_t h[8];
    uint64_t bitCount;
    size_t bufferPos;
    Byte buffer[BLOCK_SIZE];
    
    static constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    static constexpr uint32_t rotr(uint32_t x, int k) {
        return (x >> k) | (x << (32 - k));
    }
    
    static constexpr uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    
    static constexpr uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    static constexpr uint32_t sigma0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    
    static constexpr uint32_t sigma1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }
    
    static constexpr uint32_t gamma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }
    
    static constexpr uint32_t gamma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }
    
    void processBlock(const Byte* block) {
        uint32_t w[64];
        
        // Parse block into 16 32-bit words (big-endian)
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(block[i * 4 + 3]);
        }
        
        // Extend to 64 words
        for (int i = 16; i < 64; ++i) {
            w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
        }
        
        // Compression
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];
        
        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = hh + sigma1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t t2 = sigma0(a) + maj(a, b, c);
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        
        bitCount += BLOCK_SIZE * 8;
    }
};

constexpr uint32_t SHA256::K[64];

/**
 * @brief SHA-512 cryptographic hash function
 * 
 * Implements FIPS 180-4 compliant SHA-512
 */
class SHA512 {
public:
    static constexpr size_t BLOCK_SIZE = 128;
    static constexpr size_t HASH_SIZE = 64;
    
    SHA512() { reset(); }
    
    void reset() {
        h[0] = 0x6a09e667f3bcc908ULL; h[1] = 0xbb67ae8584caa73bULL;
        h[2] = 0x3c6ef372fe94f82bULL; h[3] = 0xa54ff53a5f1d36f1ULL;
        h[4] = 0x510e527fade682d1ULL; h[5] = 0x9b05688c2b3e6c1fULL;
        h[6] = 0x1f83d9abfb41bd6bULL; h[7] = 0x5be0cd19137e2179ULL;
        bitCount = 0;
        bufferPos = 0;
    }
    
    void update(const Byte* data, size_t len) {
        while (len > 0) {
            size_t copy = std::min(len, BLOCK_SIZE - bufferPos);
            std::memcpy(buffer + bufferPos, data, copy);
            bufferPos += copy;
            data += copy;
            len -= copy;
            
            if (bufferPos == BLOCK_SIZE) {
                processBlock(buffer);
                bufferPos = 0;
            }
        }
    }
    
    void update(const std::vector<Byte>& data) {
        update(data.data(), data.size());
    }
    
    std::array<Byte, HASH_SIZE> finalize() {
        uint64_t totalBits = bitCount + bufferPos * 8;
        buffer[bufferPos++] = 0x80;
        
        while (bufferPos != 112) {
            if (bufferPos == BLOCK_SIZE) {
                processBlock(buffer);
                bufferPos = 0;
            }
            buffer[bufferPos++] = 0x00;
        }
        
        for (int i = 15; i >= 0; --i) {
            buffer[bufferPos++] = static_cast<Byte>((totalBits >> (i * 8)) & 0xFF);
        }
        
        processBlock(buffer);
        
        std::array<Byte, HASH_SIZE> result;
        for (int i = 0; i < 8; ++i) {
            result[i * 8 + 0] = static_cast<Byte>((h[i] >> 56) & 0xFF);
            result[i * 8 + 1] = static_cast<Byte>((h[i] >> 48) & 0xFF);
            result[i * 8 + 2] = static_cast<Byte>((h[i] >> 40) & 0xFF);
            result[i * 8 + 3] = static_cast<Byte>((h[i] >> 32) & 0xFF);
            result[i * 8 + 4] = static_cast<Byte>((h[i] >> 24) & 0xFF);
            result[i * 8 + 5] = static_cast<Byte>((h[i] >> 16) & 0xFF);
            result[i * 8 + 6] = static_cast<Byte>((h[i] >> 8) & 0xFF);
            result[i * 8 + 7] = static_cast<Byte>(h[i] & 0xFF);
        }
        
        reset();
        return result;
    }
    
    static std::array<Byte, HASH_SIZE> hash(const std::vector<Byte>& data) {
        SHA512 ctx;
        ctx.update(data);
        return ctx.finalize();
    }

private:
    uint64_t h[8];
    uint64_t bitCount;
    size_t bufferPos;
    Byte buffer[BLOCK_SIZE];
    
    static constexpr uint64_t K[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
        0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
        0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
        0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
        0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
        0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
        0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
        0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
        0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
        0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
        0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
        0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
        0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
        0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
        0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
        0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
        0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
        0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
        0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
        0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
        0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
    };
    
    static constexpr uint64_t rotr(uint64_t x, int k) {
        return (x >> k) | (x << (64 - k));
    }
    
    static constexpr uint64_t ch(uint64_t x, uint64_t y, uint64_t z) {
        return (x & y) ^ (~x & z);
    }
    
    static constexpr uint64_t maj(uint64_t x, uint64_t y, uint64_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    static constexpr uint64_t sigma0(uint64_t x) {
        return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
    }
    
    static constexpr uint64_t sigma1(uint64_t x) {
        return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
    }
    
    static constexpr uint64_t gamma0(uint64_t x) {
        return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7);
    }
    
    static constexpr uint64_t gamma1(uint64_t x) {
        return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6);
    }
    
    void processBlock(const Byte* block) {
        uint64_t w[80];
        
        for (int i = 0; i < 16; ++i) {
            w[i] = 0;
            for (int j = 0; j < 8; ++j) {
                w[i] = (w[i] << 8) | static_cast<uint64_t>(block[i * 8 + j]);
            }
        }
        
        for (int i = 16; i < 80; ++i) {
            w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
        }
        
        uint64_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint64_t e = h[4], f = h[5], g = h[6], hh = h[7];
        
        for (int i = 0; i < 80; ++i) {
            uint64_t t1 = hh + sigma1(e) + ch(e, f, g) + K[i] + w[i];
            uint64_t t2 = sigma0(a) + maj(a, b, c);
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
        
        bitCount += BLOCK_SIZE * 8;
    }
};

constexpr uint64_t SHA512::K[80];

/**
 * @brief HMAC implementation using configurable hash function
 */
template<typename Hash>
class HMAC {
public:
    static constexpr size_t BLOCK_SIZE = Hash::BLOCK_SIZE;
    static constexpr size_t HASH_SIZE = Hash::HASH_SIZE;
    
    /**
     * @brief Compute HMAC of message with key
     * @param key Secret key
     * @param message Message to authenticate
     * @return HMAC tag
     */
    static std::array<Byte, HASH_SIZE> compute(const std::vector<Byte>& key,
                                                const std::vector<Byte>& message) {
        std::array<Byte, BLOCK_SIZE> kPrime;
        kPrime.fill(0);
        
        // Prepare padded key
        if (key.size() <= BLOCK_SIZE) {
            std::memcpy(kPrime.data(), key.data(), key.size());
        } else {
            auto hashedKey = Hash::hash(key);
            std::memcpy(kPrime.data(), hashedKey.data(), HASH_SIZE);
        }
        
        // XOR with ipad (0x36) and opad (0x5c)
        std::array<Byte, BLOCK_SIZE> iKey, oKey;
        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            iKey[i] = kPrime[i] ^ 0x36;
            oKey[i] = kPrime[i] ^ 0x5c;
        }
        
        // Inner hash: H((K' ⊕ ipad) || message)
        Hash innerHash;
        innerHash.update(iKey.data(), BLOCK_SIZE);
        innerHash.update(message);
        auto innerResult = innerHash.finalize();
        
        // Outer hash: H((K' ⊕ opad) || innerHash)
        Hash outerHash;
        outerHash.update(oKey.data(), BLOCK_SIZE);
        outerHash.update(innerResult.data(), innerResult.size());
        return outerHash.finalize();
    }
};

/**
 * @brief PBKDF2-HMAC key derivation function
 * 
 * Implements RFC 2898 PBKDF2 with HMAC-SHA256 or HMAC-SHA512
 */
class PBKDF2 {
public:
    /**
     * @brief Derive key using PBKDF2-HMAC-SHA256
     * @param password Password string
     * @param salt Salt bytes
     * @param iterations Number of iterations (≥100,000 recommended)
     * @param outputLen Desired output length
     * @return Derived key
     */
    template<typename Hash>
    static std::vector<Byte> derive(const std::string& password,
                                     const std::vector<Byte>& salt,
                                     uint32_t iterations,
                                     size_t outputLen) {
        if (outputLen == 0) return {};
        if (iterations == 0) throw std::invalid_argument("Iterations must be > 0");
        
        constexpr size_t HASH_SIZE = Hash::HASH_SIZE;
        const size_t numBlocks = (outputLen + HASH_SIZE - 1) / HASH_SIZE;
        
        std::vector<Byte> derivedKey;
        derivedKey.reserve(outputLen);
        
        // Convert password to bytes
        std::vector<Byte> passwordBytes(
            reinterpret_cast<const Byte*>(password.data()),
            reinterpret_cast<const Byte*>(password.data()) + password.size()
        );
        
        for (uint32_t i = 1; i <= numBlocks; ++i) {
            // U_1 = HMAC(password, salt || INT(i))
            std::vector<Byte> saltWithCounter = salt;
            saltWithCounter.push_back(static_cast<Byte>((i >> 24) & 0xFF));
            saltWithCounter.push_back(static_cast<Byte>((i >> 16) & 0xFF));
            saltWithCounter.push_back(static_cast<Byte>((i >> 8) & 0xFF));
            saltWithCounter.push_back(static_cast<Byte>(i & 0xFF));
            
            auto u = HMAC<Hash>::compute(passwordBytes, saltWithCounter);
            std::vector<Byte> t(u.begin(), u.end());
            
            // U_2 ... U_c
            for (uint32_t j = 2; j <= iterations; ++j) {
                u = HMAC<Hash>::compute(passwordBytes, 
                                        std::vector<Byte>(u.begin(), u.end()));
                // XOR into T
                for (size_t k = 0; k < HASH_SIZE; ++k) {
                    t[k] ^= u[k];
                }
            }
            
            derivedKey.insert(derivedKey.end(), t.begin(), t.end());
        }
        
        derivedKey.resize(outputLen);
        return derivedKey;
    }
};

/**
 * @brief Securely zero memory (prevents optimization removal)
 */
LOFER_FORCEINLINE void secureZeroMemory(void* ptr, size_t len) noexcept {
    volatile Byte* p = reinterpret_cast<volatile Byte*>(ptr);
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }
}

/**
 * @brief Securely zero a vector
 */
LOFER_FORCEINLINE void secureZero(std::vector<Byte>& vec) noexcept {
    secureZeroMemory(vec.data(), vec.size());
}

} // namespace lofer

#endif // LOFER_KDF_HPP
