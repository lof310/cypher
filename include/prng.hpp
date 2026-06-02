#ifndef LOFER_PRNG_HPP
#define LOFER_PRNG_HPP

#include "types.hpp"
#include <cstdint>
#include <vector>
#include <array>
#include <cstring>

namespace lofer {

/**
 * @brief ChaCha20-based Cryptographic PRNG
 * 
 * Security improvements over previous PRNG:
 * - Cryptographically secure (CSPRNG)
 * - Based on ChaCha20 stream cipher
 * - 256-bit key + 64-bit nonce
 * - Suitable for cryptographic operations
 * 
 * Optimizations:
 * - Force-inlined quarter round operations
 * - Unrolled keystream generation
 * - Cache-line aligned state
 */
class alignas(64) ChaCha20PRNG {
public:
    static constexpr size_t KEY_SIZE = 32;
    static constexpr size_t NONCE_SIZE = 8;
    static constexpr size_t BLOCK_SIZE = 64;
    
    /**
     * @brief Initialize ChaCha20 with key and nonce
     * @param key 32-byte secret key
     * @param nonce 8-byte nonce
     */
    LOFER_FORCEINLINE void init(const std::array<Byte, KEY_SIZE>& key,
                                 const std::array<Byte, NONCE_SIZE>& nonce) noexcept {
        // Constants "expand 32-byte k"
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        
        // Load key (little-endian)
        for (int i = 0; i < 8; ++i) {
            state[4 + i] = loadLittleEndian32(key.data() + i * 4);
        }
        
        // Counter starts at 0
        state[12] = 0;
        state[13] = 0;
        
        // Load nonce (8 bytes, padded with zeros)
        state[14] = loadLittleEndian32(nonce.data());
        state[15] = loadLittleEndian32(nonce.data() + 4);
        
        bufferPos = BLOCK_SIZE;  // Force first block generation
    }
    
    /**
     * @brief Seed from a single seed array (split into key + nonce)
     * @param seedData At least 40 bytes (32 key + 8 nonce)
     */
    LOFER_FORCEINLINE void seed(const std::vector<Byte>& seedData) noexcept {
        std::array<Byte, KEY_SIZE> key{};
        std::array<Byte, NONCE_SIZE> nonce{};
        
        size_t copyLen = std::min(seedData.size(), size_t(KEY_SIZE));
        std::memcpy(key.data(), seedData.data(), copyLen);
        
        if (seedData.size() > KEY_SIZE) {
            copyLen = std::min(seedData.size() - KEY_SIZE, size_t(NONCE_SIZE));
            std::memcpy(nonce.data(), seedData.data() + KEY_SIZE, copyLen);
        } else {
            // Derive nonce from key if not enough data
            for (size_t i = 0; i < NONCE_SIZE; ++i) {
                nonce[i] = key[(i + 16) % KEY_SIZE];
            }
        }
        
        init(key, nonce);
    }
    
    /**
     * @brief Generate next 32-bit random value
     * @return 32-bit pseudo-random number
     */
    LOFER_FORCEINLINE uint32_t next() noexcept {
        if (bufferPos >= BLOCK_SIZE) {
            generateBlock();
            bufferPos = 0;
        }
        
        uint32_t result = loadLittleEndian32(buffer + bufferPos);
        bufferPos += 4;
        return result;
    }
    
    /**
     * @brief Generate random value in range [0, max)
     * @param max Upper bound (exclusive)
     * @return Random value in [0, max)
     */
    LOFER_FORCEINLINE uint32_t nextBounded(uint32_t max) noexcept {
        if (LOFER_UNLIKELY(max == 0)) return 0;
        
        // Branchless power-of-2 check
        const uint32_t isPow2 = ((max & (max - 1)) == 0);
        
        // Power of 2: use bitmask (fast path)
        const uint32_t maskResult = next() & (max - 1);
        
        // Non-power of 2: use rejection sampling to avoid bias
        uint32_t rejectResult = 0;
        if (LOFER_UNLIKELY(!isPow2)) {
            const uint32_t threshold = (~max + 1) % max;
            uint32_t x;
            do {
                x = next();
            } while (LOFER_UNLIKELY(x < threshold));
            rejectResult = x % max;
        }
        
        return isPow2 ? maskResult : rejectResult;
    }

private:
    alignas(64) uint32_t state[16];  // ChaCha20 state
    alignas(64) Byte buffer[BLOCK_SIZE];  // Keystream buffer
    size_t bufferPos;  // Current position in buffer
    
    /**
     * @brief Load 32-bit little-endian value
     */
    LOFER_FORCEINLINE static uint32_t loadLittleEndian32(const Byte* p) noexcept {
        return static_cast<uint32_t>(p[0]) |
               (static_cast<uint32_t>(p[1]) << 8) |
               (static_cast<uint32_t>(p[2]) << 16) |
               (static_cast<uint32_t>(p[3]) << 24);
    }
    
    /**
     * @brief Store 32-bit little-endian value
     */
    LOFER_FORCEINLINE static void storeLittleEndian32(Byte* p, uint32_t v) noexcept {
        p[0] = static_cast<Byte>(v & 0xFF);
        p[1] = static_cast<Byte>((v >> 8) & 0xFF);
        p[2] = static_cast<Byte>((v >> 16) & 0xFF);
        p[3] = static_cast<Byte>((v >> 24) & 0xFF);
    }
    
    /**
     * @brief ChaCha20 quarter round
     */
    LOFER_FORCEINLINE static void quarterRound(uint32_t& a, uint32_t& b, 
                                                uint32_t& c, uint32_t& d) noexcept {
        a += b; d ^= a; d = rotl(d, 16);
        c += d; b ^= c; b = rotl(b, 12);
        a += b; d ^= a; d = rotl(d, 8);
        c += d; b ^= c; b = rotl(b, 7);
    }
    
    /**
     * @brief Rotate left
     */
    LOFER_FORCEINLINE static uint32_t rotl(uint32_t x, int k) noexcept {
        return (x << k) | (x >> (32 - k));
    }
    
    /**
     * @brief Generate 64-byte keystream block
     */
    LOFER_NOINLINE void generateBlock() noexcept {
        uint32_t working[16];
        
        // Copy state to working array
        for (int i = 0; i < 16; ++i) {
            working[i] = state[i];
        }
        
        // 20 rounds (10 double rounds)
        for (int r = 0; r < 10; ++r) {
            // Column rounds
            quarterRound(working[0], working[4], working[8], working[12]);
            quarterRound(working[1], working[5], working[9], working[13]);
            quarterRound(working[2], working[6], working[10], working[14]);
            quarterRound(working[3], working[7], working[11], working[15]);
            
            // Diagonal rounds
            quarterRound(working[0], working[5], working[10], working[15]);
            quarterRound(working[1], working[6], working[11], working[12]);
            quarterRound(working[2], working[7], working[8], working[13]);
            quarterRound(working[3], working[4], working[9], working[14]);
        }
        
        // Add original state
        for (int i = 0; i < 16; ++i) {
            storeLittleEndian32(buffer + i * 4, working[i] + state[i]);
        }
        
        // Increment counter
        state[12]++;
        if (state[12] == 0) {
            state[13]++;
        }
    }
};

// Backward compatibility alias
using PRNG = ChaCha20PRNG;

} // namespace lofer

#endif // LOFER_PRNG_HPP
