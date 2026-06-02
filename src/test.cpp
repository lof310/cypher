/**
 * Lofer Cipher Test Suite
 * 
 * Comprehensive tests for encryption/decryption correctness,
 * edge cases, and security properties.
 */

#include "cipher.hpp"
#include "file.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <cassert>
#include <cstring>
#include <filesystem>

namespace fs = std::filesystem;

using namespace lofer;

// Test result tracking
struct TestResult {
    std::string name;
    bool passed;
    std::string message;
};

std::vector<TestResult> testResults;

void reportTest(const std::string& name, bool passed, const std::string& message = "") {
    testResults.push_back({name, passed, message});
    std::cout << (passed ? "[PASS] " : "[FAIL] ") << name;
    if (!message.empty()) {
        std::cout << ": " << message;
    }
    std::cout << std::endl;
}

// Generate random data for testing
std::vector<Byte> generateRandomData(size_t size) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::vector<Byte> data(size);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<Byte>(dis(gen));
    }
    return data;
}

// Test: Empty file
void testEmptyFile() {
    const std::string password = "test_password_123";
    
    std::vector<Byte> plaintext = {};
    auto encrypted = encrypt(plaintext, password);
    auto decrypted = decrypt(encrypted, password);
    
    bool passed = (decrypted.size() == 0);
    reportTest("Empty file", passed);
}

// Test: Single byte
void testSingleByte() {
    const std::string password = "test_password_123";
    
    std::vector<Byte> plaintext = {42};
    auto encrypted = encrypt(plaintext, password);
    auto decrypted = decrypt(encrypted, password);
    
    bool passed = (decrypted.size() == 1 && decrypted[0] == 42);
    reportTest("Single byte", passed);
}

// Test: Small file (64 bytes)
void testSmallFile() {
    const std::string password = "test_password_123";
    
    auto plaintext = generateRandomData(64);
    auto encrypted = encrypt(plaintext, password);
    auto decrypted = decrypt(encrypted, password);
    
    bool passed = (decrypted == plaintext);
    reportTest("Small file (64 bytes)", passed);
}

// Test: Medium file (10 KB)
void testMediumFile() {
    const std::string password = "test_password_123";
    
    auto plaintext = generateRandomData(10 * 1024);
    auto encrypted = encrypt(plaintext, password);
    auto decrypted = decrypt(encrypted, password);
    
    bool passed = (decrypted == plaintext);
    reportTest("Medium file (10 KB)", passed);
}

// Test: Large file (1 MB)
void testLargeFile() {
    const std::string password = "test_password_123";
    
    // Use smaller size for faster testing with PBKDF2
    auto plaintext = generateRandomData(64 * 1024);  // 64 KB instead of 1 MB
    auto encrypted = encrypt(plaintext, password);
    auto decrypted = decrypt(encrypted, password);
    
    bool passed = (decrypted == plaintext);
    reportTest("Large file (64 KB)", passed);
}

// Test: Different passwords produce different ciphertexts
void testDifferentPasswords() {
    std::vector<Byte> plaintext = generateRandomData(128);
    
    auto encrypted1 = encrypt(plaintext, "password1");
    auto encrypted2 = encrypt(plaintext, "password2");
    
    // Ciphertexts should differ (at least in salt or content)
    bool passed = (encrypted1 != encrypted2);
    
    // Both should decrypt correctly
    auto decrypted1 = decrypt(encrypted1, "password1");
    auto decrypted2 = decrypt(encrypted2, "password2");
    passed = passed && (decrypted1 == plaintext) && (decrypted2 == plaintext);
    
    reportTest("Different passwords", passed);
}

// Test: Wrong password detection
void testWrongPassword() {
    const std::string password = "correct_password";
    const std::string wrongPassword = "wrong_password";
    
    std::vector<Byte> plaintext = generateRandomData(256);
    auto encrypted = encrypt(plaintext, password);
    
    // Decryption with wrong password should throw due to HMAC verification failure
    bool threwException = false;
    try {
        auto decrypted = decrypt(encrypted, wrongPassword);
        (void)decrypted;  // Suppress unused warning
    } catch (const std::runtime_error& e) {
        threwException = true;
        // Verify it's an authentication error
        bool isAuthError = std::string(e.what()).find("HMAC") != std::string::npos ||
                           std::string(e.what()).find("authentication") != std::string::npos;
        reportTest("Wrong password detection", isAuthError, 
                   isAuthError ? "" : std::string("Expected auth error, got: ") + e.what());
        return;
    }
    
    reportTest("Wrong password detection", threwException, 
               "Expected exception for wrong password");
}

// Test: Text content preservation
void testTextContent() {
    const std::string password = "text_test_password";
    
    std::string text = "Hello, World! This is a test of the Lofer cipher. "
                       "The quick brown fox jumps over the lazy dog. "
                       "Special characters: !@#$%^&*()_+-=[]{}|;:',.<>?/`~";
    
    std::vector<Byte> plaintext(text.begin(), text.end());
    auto encrypted = encrypt(plaintext, password);
    auto decrypted = decrypt(encrypted, password);
    
    std::string decryptedText(decrypted.begin(), decrypted.end());
    bool passed = (decryptedText == text);
    reportTest("Text content preservation", passed);
}

// Test: All zeros data
void testAllZeros() {
    const std::string password = "zeros_test";
    
    std::vector<Byte> plaintext(1024, 0);
    auto encrypted = encrypt(plaintext, password);
    auto decrypted = decrypt(encrypted, password);
    
    bool passed = (decrypted == plaintext);
    reportTest("All zeros data", passed);
}

// Test: All ones data
void testAllOnes() {
    const std::string password = "ones_test";
    
    std::vector<Byte> plaintext(1024, 0xFF);
    auto encrypted = encrypt(plaintext, password);
    auto decrypted = decrypt(encrypted, password);
    
    bool passed = (decrypted == plaintext);
    reportTest("All ones data", passed);
}

// Test: File I/O
void testFileIO() {
    const std::string password = "file_io_test";
    const std::string testFile = "/tmp/lofer_test_input.bin";
    const std::string encryptedFile = "/tmp/lofer_test_encrypted.bin";
    const std::string decryptedFile = "/tmp/lofer_test_decrypted.bin";
    
    try {
        // Create test file
        auto testData = generateRandomData(512);
        writeFile(testFile, testData);
        
        // Encrypt
        encryptFile(testFile, encryptedFile, password);
        
        // Decrypt
        decryptFile(encryptedFile, decryptedFile, password);
        
        // Verify
        auto decryptedData = readFile(decryptedFile);
        bool passed = (decryptedData == testData);
        reportTest("File I/O", passed);
        
        // Cleanup
        fs::remove(testFile);
        fs::remove(encryptedFile);
        fs::remove(decryptedFile);
    } catch (const std::exception& e) {
        reportTest("File I/O", false, e.what());
    }
}

// Test: Salt uniqueness (semantic security)
void testSaltUniqueness() {
    const std::string password = "salt_test";
    std::vector<Byte> plaintext = generateRandomData(128);
    
    // Encrypt same plaintext multiple times
    auto enc1 = encrypt(plaintext, password);
    auto enc2 = encrypt(plaintext, password);
    auto enc3 = encrypt(plaintext, password);
    
    // All ciphertexts should be different due to random salt
    bool passed = (enc1 != enc2) && (enc2 != enc3) && (enc1 != enc3);
    
    // All should decrypt to same plaintext
    auto dec1 = decrypt(enc1, password);
    auto dec2 = decrypt(enc2, password);
    auto dec3 = decrypt(enc3, password);
    passed = passed && (dec1 == plaintext) && (dec2 == plaintext) && (dec3 == plaintext);
    
    reportTest("Salt uniqueness", passed);
}

// Test: HMAC authentication with wrong password
void testHMACAuthentication() {
    const std::string password = "auth_test_password";
    const std::string wrongPassword = "wrong_auth_password";
    
    std::vector<Byte> plaintext = generateRandomData(512);
    auto encrypted = encrypt(plaintext, password);
    
    // Verify HMAC fails with wrong password
    bool hmacFailed = false;
    try {
        auto decrypted = decrypt(encrypted, wrongPassword);
        (void)decrypted;
    } catch (const std::runtime_error& e) {
        hmacFailed = true;
    }
    
    reportTest("HMAC authentication", hmacFailed, 
               hmacFailed ? "" : "Expected HMAC verification failure");
}

// Test: Round trip consistency - reduced iterations for faster testing
void testRoundTripConsistency() {
    const std::string password = "roundtrip_test";
    
    // Test key boundary sizes only
    std::vector<size_t> sizes = {1, 2, 16, 32, 64, 128, 256};
    
    bool allPassed = true;
    for (size_t size : sizes) {
        auto plaintext = generateRandomData(size);
        auto encrypted = encrypt(plaintext, password);
        auto decrypted = decrypt(encrypted, password);
        
        if (decrypted != plaintext) {
            allPassed = false;
            break;
        }
    }
    
    reportTest("Round trip consistency", allPassed);
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Lofer Cipher Test Suite\n";
    std::cout << "========================================\n\n";
    
    // Run all tests
    testEmptyFile();
    testSingleByte();
    testSmallFile();
    testMediumFile();
    testLargeFile();
    testDifferentPasswords();
    testWrongPassword();
    testTextContent();
    testAllZeros();
    testAllOnes();
    testFileIO();
    testSaltUniqueness();
    testHMACAuthentication();
    testRoundTripConsistency();
    
    // Summary
    std::cout << "\n========================================\n";
    std::cout << "Test Summary\n";
    std::cout << "========================================\n";
    
    int passed = 0, failed = 0;
    for (const auto& result : testResults) {
        if (result.passed) {
            ++passed;
        } else {
            ++failed;
        }
    }
    
    std::cout << "Passed: " << passed << "/" << testResults.size() << std::endl;
    std::cout << "Failed: " << failed << "/" << testResults.size() << std::endl;
    
    if (failed > 0) {
        std::cout << "\nFailed tests:\n";
        for (const auto& result : testResults) {
            if (!result.passed) {
                std::cout << "  - " << result.name;
                if (!result.message.empty()) {
                    std::cout << ": " << result.message;
                }
                std::cout << std::endl;
            }
        }
    }
    
    return failed == 0 ? 0 : 1;
}
