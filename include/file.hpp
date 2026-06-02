#ifndef LOFER_FILE_HPP
#define LOFER_FILE_HPP

#include "types.hpp"
#include "cipher.hpp"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace lofer {

/**
 * @brief Read entire file into byte vector
 * @param path File path
 * @return File contents as byte vector
 * @throws std::runtime_error if file cannot be read
 */
inline std::vector<Byte> readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    
    std::streamsize size = file.tellg();
    if (size < 0) {
        throw std::runtime_error("Failed to get file size: " + path);
    }
    
    file.seekg(0, std::ios::beg);
    
    std::vector<Byte> buffer(static_cast<size_t>(size));
    if (size > 0 && !file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file: " + path);
    }
    
    return buffer;
}

/**
 * @brief Write byte vector to file
 * @param path File path
 * @param data Data to write
 * @throws std::runtime_error if file cannot be written
 */
inline void writeFile(const std::string& path, const std::vector<Byte>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot create file: " + path);
    }
    
    if (!data.empty()) {
        file.write(reinterpret_cast<const char*>(data.data()), 
                   static_cast<std::streamsize>(data.size()));
    }
    
    if (!file) {
        throw std::runtime_error("Failed to write file: " + path);
    }
}

/**
 * @brief Encrypt a file
 * @param inputPath Input file path
 * @param outputPath Output file path (default: input.enc)
 * @param password Encryption password
 * @param config Cipher configuration (optional)
 * @throws std::exception on error
 */
inline void encryptFile(const std::string& inputPath, 
                        const std::string& outputPath,
                        const std::string& password,
                        const CipherConfig& config = CipherConfig()) {
    auto data = readFile(inputPath);
    auto encrypted = encrypt(data, password, config);
    writeFile(outputPath, encrypted);
}

/**
 * @brief Decrypt a file
 * @param inputPath Input file path
 * @param outputPath Output file path (default: input.dec or input without .enc)
 * @param password Decryption password
 * @param config Cipher configuration (optional)
 * @throws std::exception on error
 */
inline void decryptFile(const std::string& inputPath, 
                        const std::string& outputPath,
                        const std::string& password,
                        const CipherConfig& config = CipherConfig()) {
    auto data = readFile(inputPath);
    auto decrypted = decrypt(data, password, config);
    writeFile(outputPath, decrypted);
}

/**
 * @brief Process all files in a directory
 * @param dirPath Directory path
 * @param password Password for encryption/decryption
 * @param doEncrypt true for encryption, false for decryption
 * @param recursive Whether to process subdirectories
 * @param config Cipher configuration (optional)
 * @return Number of files processed
 */
inline size_t processDirectory(const std::string& dirPath,
                                const std::string& password,
                                bool doEncrypt,
                                bool recursive = false,
                                const CipherConfig& config = CipherConfig()) {
    size_t count = 0;
    
    try {
        if (recursive) {
            for (const auto& entry : fs::recursive_directory_iterator(dirPath)) {
                if (entry.is_regular_file()) {
                    std::string inputPath = entry.path().string();
                    std::string outputPath;
                    
                    if (doEncrypt) {
                        // Skip already encrypted files
                        if (inputPath.size() > 4 && 
                            inputPath.substr(inputPath.size() - 4) == ".enc") {
                            continue;
                        }
                        outputPath = inputPath + ".enc";
                    } else {
                        // Skip non-encrypted files
                        if (inputPath.size() <= 4 || 
                            inputPath.substr(inputPath.size() - 4) != ".enc") {
                            continue;
                        }
                        outputPath = inputPath.substr(0, inputPath.size() - 4);
                    }
                    
                    try {
                        if (doEncrypt) {
                            encryptFile(inputPath, outputPath, password, config);
                        } else {
                            decryptFile(inputPath, outputPath, password, config);
                        }
                        ++count;
                    } catch (const std::exception& e) {
                        std::cerr << "Error processing " << inputPath << ": " << e.what() << std::endl;
                    }
                }
            }
        } else {
            for (const auto& entry : fs::directory_iterator(dirPath)) {
                if (entry.is_regular_file()) {
                    std::string inputPath = entry.path().string();
                    std::string outputPath;
                    
                    if (doEncrypt) {
                        // Skip already encrypted files
                        if (inputPath.size() > 4 && 
                            inputPath.substr(inputPath.size() - 4) == ".enc") {
                            continue;
                        }
                        outputPath = inputPath + ".enc";
                    } else {
                        // Skip non-encrypted files
                        if (inputPath.size() <= 4 || 
                            inputPath.substr(inputPath.size() - 4) != ".enc") {
                            continue;
                        }
                        outputPath = inputPath.substr(0, inputPath.size() - 4);
                    }
                    
                    try {
                        if (doEncrypt) {
                            encryptFile(inputPath, outputPath, password, config);
                        } else {
                            decryptFile(inputPath, outputPath, password, config);
                        }
                        ++count;
                    } catch (const std::exception& e) {
                        std::cerr << "Error processing " << inputPath << ": " << e.what() << std::endl;
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error iterating directory: " << e.what() << std::endl;
    }
    
    return count;
}

/**
 * @brief Print usage information
 */
inline void printUsage(const char* progName) {
    std::cout << "Lofer Cipher - Symmetric-key block cipher\n\n"
              << "Usage: " << progName << " [options]\n\n"
              << "Options:\n"
              << "  -e <file>           Encrypt the specified file\n"
              << "  -d <file>           Decrypt the specified file\n"
              << "  -o <output>         Output file path\n"
              << "  -D <dir>            Process all files in directory\n"
              << "  -r                  Recursive mode (with -D)\n"
              << "  -p <password>       Password (or will prompt if not provided)\n"
              << "  --rounds <N>        Number of SPN rounds (8-32, default: 16)\n"
              << "  --hash <type>       Hash algorithm: sha256 or sha512 (default: sha256)\n"
              << "  --iterations <N>    PBKDF2 iterations (default: 100000)\n"
              << "  --no-auth           Disable HMAC authentication (not recommended)\n"
              << "  -h, --help          Show this help message\n\n"
              << "Examples:\n"
              << "  " << progName << " -e secret.txt -o secret.enc -p \"mypassword\"\n"
              << "  " << progName << " -d secret.enc -p \"mypassword\"\n"
              << "  " << progName << " -D ./docs -r -p \"mypassword\"\n"
              << "  " << progName << " -e data.bin --rounds 24 --hash sha512 --iterations 200000\n";
}

} // namespace lofer

#endif // LOFER_FILE_HPP
