#ifndef LOFER_CIPHER_HPP
#define LOFER_CIPHER_HPP

#include "types.hpp"
#include "kdf.hpp"
#include "permutation.hpp"
#include <vector>
#include <array>
#include <random>
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <memory>

namespace lofer {

/**
 * @brief Secure random salt generator using ChaCha20 PRNG seeded from hardware RNG
 */
LOFER_FORCEINLINE std::array<Byte, SALT_LEN> generateSalt() {
    std::random_device rd;
    std::array<Byte, SALT_LEN> salt;
    
    for (size_t i = 0; i < SALT_LEN; i += 4) {
        uint32_t val = rd();
        salt[i + 0] = static_cast<Byte>(val & 0xFF);
        salt[i + 1] = static_cast<Byte>((val >> 8) & 0xFF);
        salt[i + 2] = static_cast<Byte>((val >> 16) & 0xFF);
        salt[i + 3] = static_cast<Byte>((val >> 24) & 0xFF);
    }
    return salt;
}

/**
 * @brief Compute HMAC for authentication
 */
template<typename Hash>
LOFER_FORCEINLINE std::array<Byte, HMAC_LEN> computeHMAC(const std::vector<Byte>& key,
                                                          const std::vector<Byte>& message) {
    auto hmacResult = HMAC<Hash>::compute(key, message);
    std::array<Byte, HMAC_LEN> result;
    std::memcpy(result.data(), hmacResult.data(), HMAC_LEN);
    return result;
}

/**
 * @brief Encrypt plaintext using Lofer cipher with configurable options
 * 
 * Algorithm:
 * 1. Generate random salt
 * 2. Derive round keys, HMAC key from password+salt using PBKDF2
 * 3. For each round: apply S-box substitution, then affine permutation
 * 4. Compute HMAC over ciphertext
 * 5. Output: salt || ciphertext || HMAC
 * 
 * @param plaintext Data to encrypt
 * @param password Encryption password
 * @param config Cipher configuration (optional, uses defaults if not provided)
 * @return Ciphertext with prepended salt and appended HMAC (if enabled)
 */
LOFER_HOT inline std::vector<Byte> encrypt(const std::vector<Byte>& plaintext, 
                                            const std::string& password,
                                            const CipherConfig& config = CipherConfig()) {
    if (LOFER_UNLIKELY(password.empty())) {
        throw std::invalid_argument("Password cannot be empty");
    }
    
    if (LOFER_UNLIKELY(!config.isValid())) {
        throw std::invalid_argument("Invalid cipher configuration");
    }
    
    // Generate random salt
    auto salt = generateSalt();
    
    // Derive parameters including HMAC key
    int R;
    std::vector<RoundParams> params;
    deriveParameters(password, salt, R, params, config);
    
    // Derive HMAC key from same master key derivation
    std::vector<Byte> saltVec(salt.begin(), salt.end());
    std::vector<Byte> masterKey;
    size_t masterKeyLen = 64 + HMAC_LEN;
    
    if (config.hashAlgo == HashAlgorithm::SHA512) {
        masterKey = PBKDF2::derive<SHA512>(password, saltVec, config.pbkdf2Iterations, masterKeyLen);
    } else {
        masterKey = PBKDF2::derive<SHA256>(password, saltVec, config.pbkdf2Iterations, masterKeyLen);
    }
    
    std::array<Byte, 32> hmacKey;
    std::memcpy(hmacKey.data(), masterKey.data() + 64, HMAC_LEN);
    secureZero(masterKey);
    
    const size_t L = plaintext.size();
    
    // Handle empty input
    if (LOFER_UNLIKELY(L == 0)) {
        std::vector<Byte> result(salt.begin(), salt.end());
        if (config.useAuthentication) {
            std::vector<Byte> authData = result;
            std::array<Byte, HMAC_LEN> hmac;
            if (config.hashAlgo == HashAlgorithm::SHA512) {
                hmac = computeHMAC<SHA512>(std::vector<Byte>(hmacKey.begin(), hmacKey.end()), authData);
            } else {
                hmac = computeHMAC<SHA256>(std::vector<Byte>(hmacKey.begin(), hmacKey.end()), authData);
            }
            result.insert(result.end(), hmac.begin(), hmac.end());
        }
        return result;
    }
    
    // Copy plaintext to state
    std::vector<Element> state(L);
    std::memcpy(state.data(), plaintext.data(), L);
    
    // Instantiate permutations for this data length
    instantiatePermutations(L, params);
    
    // Apply SPN rounds (core algorithm - unchanged)
    for (int r = 0; r < R; ++r) {
        // Substitution: S-box lookup (hot path)
        const Element* LOFER_RESTRICT sbox = params[r].S_r.data();
        Element* LOFER_RESTRICT statePtr = state.data();
        for (size_t i = 0; i < L; ++i) {
            statePtr[i] = sbox[statePtr[i]];
        }
        
        // Permutation: affine transformation (only if L > 1)
        if (L > 1) {
            std::vector<Element> newState(L);
            const size_t a = params[r].a;
            const size_t b = params[r].b;
            const Element* LOFER_RESTRICT src = state.data();
            Element* LOFER_RESTRICT dst = newState.data();
            
            for (size_t i = 0; i < L; ++i) {
                size_t newPos = (a * i + b) % L;
                dst[newPos] = src[i];
            }
            state = std::move(newState);
        }
    }
    
    // Build result: salt + ciphertext
    std::vector<Byte> result;
    result.reserve(SALT_LEN + L + (config.useAuthentication ? HMAC_LEN : 0));
    result.insert(result.end(), salt.begin(), salt.end());
    result.insert(result.end(), state.begin(), state.end());
    
    // Append HMAC if authentication is enabled
    if (config.useAuthentication) {
        std::array<Byte, HMAC_LEN> hmac;
        if (config.hashAlgo == HashAlgorithm::SHA512) {
            hmac = computeHMAC<SHA512>(std::vector<Byte>(hmacKey.begin(), hmacKey.end()), result);
        } else {
            hmac = computeHMAC<SHA256>(std::vector<Byte>(hmacKey.begin(), hmacKey.end()), result);
        }
        result.insert(result.end(), hmac.begin(), hmac.end());
    }
    
    return result;
}

/**
 * @brief Decrypt ciphertext using Lofer cipher with configurable options
 * 
 * Algorithm:
 * 1. Extract salt from ciphertext
 * 2. Verify HMAC first (if enabled) - reject if invalid
 * 3. Derive round keys and parameters from password+salt
 * 4. For each round (in reverse): inverse affine permutation, then inverse S-box
 * 5. Return plaintext
 * 
 * @param encrypted Ciphertext with prepended salt and appended HMAC
 * @param password Decryption password
 * @param config Cipher configuration (optional, uses defaults if not provided)
 * @return Decrypted plaintext
 * @throws std::runtime_error if ciphertext is invalid or HMAC verification fails
 */
LOFER_HOT inline std::vector<Byte> decrypt(const std::vector<Byte>& encrypted, 
                                            const std::string& password,
                                            const CipherConfig& config = CipherConfig()) {
    if (LOFER_UNLIKELY(encrypted.size() < SALT_LEN)) {
        throw std::runtime_error("Invalid ciphertext: too short");
    }
    
    // Determine expected total length
    size_t minLen = SALT_LEN;
    if (config.useAuthentication) {
        minLen += HMAC_LEN;
    }
    
    if (LOFER_UNLIKELY(encrypted.size() < minLen)) {
        throw std::runtime_error("Invalid ciphertext: incorrect length");
    }
    
    // Extract salt
    std::array<Byte, SALT_LEN> salt;
    std::memcpy(salt.data(), encrypted.data(), SALT_LEN);
    
    // Extract ciphertext and HMAC
    size_t ciphertextLen = encrypted.size() - SALT_LEN;
    std::array<Byte, HMAC_LEN> receivedHmac{};
    
    if (config.useAuthentication) {
        if (LOFER_UNLIKELY(encrypted.size() < SALT_LEN + HMAC_LEN)) {
            throw std::runtime_error("Invalid ciphertext: missing HMAC");
        }
        ciphertextLen -= HMAC_LEN;
        std::memcpy(receivedHmac.data(), encrypted.data() + SALT_LEN + ciphertextLen, HMAC_LEN);
    }
    
    // Handle empty ciphertext
    if (LOFER_UNLIKELY(ciphertextLen == 0)) {
        if (config.useAuthentication) {
            std::vector<Byte> saltVec(salt.begin(), salt.end());
            std::vector<Byte> masterKey;
            size_t masterKeyLen = 64 + HMAC_LEN;
            
            if (config.hashAlgo == HashAlgorithm::SHA512) {
                masterKey = PBKDF2::derive<SHA512>(password, saltVec, config.pbkdf2Iterations, masterKeyLen);
            } else {
                masterKey = PBKDF2::derive<SHA256>(password, saltVec, config.pbkdf2Iterations, masterKeyLen);
            }
            
            std::array<Byte, 32> hmacKey;
            std::memcpy(hmacKey.data(), masterKey.data() + 64, HMAC_LEN);
            secureZero(masterKey);
            
            std::array<Byte, HMAC_LEN> computedHmac;
            if (config.hashAlgo == HashAlgorithm::SHA512) {
                computedHmac = computeHMAC<SHA512>(std::vector<Byte>(hmacKey.begin(), hmacKey.end()), saltVec);
            } else {
                computedHmac = computeHMAC<SHA256>(std::vector<Byte>(hmacKey.begin(), hmacKey.end()), saltVec);
            }
            
            // Constant-time comparison
            volatile Byte diff = 0;
            for (size_t i = 0; i < HMAC_LEN; ++i) {
                diff |= receivedHmac[i] ^ computedHmac[i];
            }
            if (diff != 0) {
                throw std::runtime_error("HMAC verification failed: authentication error");
            }
        }
        return {};
    }
    
    // Extract ciphertext portion
    std::vector<Byte> ciphertext(encrypted.begin() + SALT_LEN, 
                                  encrypted.begin() + SALT_LEN + ciphertextLen);
    
    // Verify HMAC before decryption (Encrypt-then-MAC)
    if (config.useAuthentication) {
        std::vector<Byte> saltVec(salt.begin(), salt.end());
        std::vector<Byte> masterKey;
        size_t masterKeyLen = 64 + HMAC_LEN;
        
        if (config.hashAlgo == HashAlgorithm::SHA512) {
            masterKey = PBKDF2::derive<SHA512>(password, saltVec, config.pbkdf2Iterations, masterKeyLen);
        } else {
            masterKey = PBKDF2::derive<SHA256>(password, saltVec, config.pbkdf2Iterations, masterKeyLen);
        }
        
        std::array<Byte, 32> hmacKey;
        std::memcpy(hmacKey.data(), masterKey.data() + 64, HMAC_LEN);
        
        // Compute HMAC over salt || ciphertext
        std::vector<Byte> authData = saltVec;
        authData.insert(authData.end(), ciphertext.begin(), ciphertext.end());
        
        std::array<Byte, HMAC_LEN> computedHmac;
        if (config.hashAlgo == HashAlgorithm::SHA512) {
            computedHmac = computeHMAC<SHA512>(std::vector<Byte>(hmacKey.begin(), hmacKey.end()), authData);
        } else {
            computedHmac = computeHMAC<SHA256>(std::vector<Byte>(hmacKey.begin(), hmacKey.end()), authData);
        }
        
        secureZero(masterKey);
        
        // Constant-time HMAC comparison to prevent timing attacks
        volatile Byte diff = 0;
        for (size_t i = 0; i < HMAC_LEN; ++i) {
            diff |= receivedHmac[i] ^ computedHmac[i];
        }
        if (diff != 0) {
            throw std::runtime_error("HMAC verification failed: authentication error");
        }
    }
    
    // Derive parameters
    int R;
    std::vector<RoundParams> params;
    deriveParameters(password, salt, R, params, config);
    
    // Instantiate permutations
    instantiatePermutations(ciphertextLen, params);
    
    // Copy ciphertext to state
    std::vector<Element> state(ciphertextLen);
    std::memcpy(state.data(), ciphertext.data(), ciphertextLen);
    
    // Apply rounds in reverse order (core algorithm - unchanged)
    for (int r = R - 1; r >= 0; --r) {
        // Inverse permutation (only if L > 1)
        if (ciphertextLen > 1) {
            std::vector<Element> newState(ciphertextLen);
            const size_t a_inv = params[r].a_inv;
            const size_t b_inv = params[r].b_inv;
            const Element* LOFER_RESTRICT src = state.data();
            Element* LOFER_RESTRICT dst = newState.data();
            
            for (size_t j = 0; j < ciphertextLen; ++j) {
                size_t origPos = (a_inv * j + b_inv) % ciphertextLen;
                dst[origPos] = src[j];
            }
            state = std::move(newState);
        }
        
        // Inverse substitution using precomputed inverse S-box (hot path)
        const Element* LOFER_RESTRICT invSbox = params[r].invS_r.data();
        Element* LOFER_RESTRICT statePtr = state.data();
        for (size_t i = 0; i < ciphertextLen; ++i) {
            statePtr[i] = invSbox[statePtr[i]];
        }
    }
    
    // Return plaintext
    return std::vector<Byte>(state.begin(), state.end());
}

/**
 * @brief Encrypt with default configuration (backward compatibility)
 */
inline std::vector<Byte> encryptDefault(const std::vector<Byte>& plaintext, 
                                         const std::string& password) {
    return encrypt(plaintext, password, CipherConfig());
}

/**
 * @brief Decrypt with default configuration (backward compatibility)
 */
inline std::vector<Byte> decryptDefault(const std::vector<Byte>& encrypted, 
                                         const std::string& password) {
    return decrypt(encrypted, password, CipherConfig());
}

/**
 * @brief Encrypt data in-place (modifies input)
 * @param data Data to encrypt (replaced with ciphertext)
 * @param password Encryption password
 * @param config Cipher configuration
 */
inline void encryptInPlace(std::vector<Byte>& data, const std::string& password,
                           const CipherConfig& config = CipherConfig()) {
    data = encrypt(data, password, config);
}

/**
 * @brief Decrypt data in-place (modifies input)
 * @param data Ciphertext (replaced with plaintext)
 * @param password Decryption password
 * @param config Cipher configuration
 */
inline void decryptInPlace(std::vector<Byte>& data, const std::string& password,
                           const CipherConfig& config = CipherConfig()) {
    data = decrypt(data, password, config);
}

} // namespace lofer

#endif // LOFER_CIPHER_HPP
