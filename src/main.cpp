/**
 * Lofer Cipher - Main Entry Point
 * 
 * A symmetric-key block cipher using Substitution-Permutation Network (SPN) design.
 */

#include "file.hpp"
#include "cipher.hpp"
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>

#ifndef _WIN32
#include <termios.h>
#include <unistd.h>
#endif

namespace lofer {

/**
 * @brief Read password from terminal without echoing
 * @return Password string
 */
inline std::string readPassword() {
    std::cout << "Enter password: ";
    
#ifdef _WIN32
    // Windows implementation
    std::string password;
    char ch;
    while ((ch = _getch()) != '\r' && ch != '\n') {
        if (ch == '\b' || ch == 127) {  // Backspace
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
            }
        } else if (ch >= 32 && ch <= 126) {  // Printable characters
            password.push_back(ch);
            std::cout << '*';
        }
    }
    std::cout << std::endl;
    return password;
#else
    // POSIX implementation
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    
    std::string password;
    std::getline(std::cin, password);
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cout << std::endl;
    
    return password;
#endif
}

} // namespace lofer

int main(int argc, char* argv[]) {
    using namespace lofer;
    
    std::string inputFile;
    std::string outputFile;
    std::string inputDir;
    std::string password;
    bool encryptMode = false;
    bool decryptMode = false;
    bool recursive = false;
    bool dirMode = false;
    
    // Cipher configuration options
    CipherConfig config;
    bool customRounds = false;
    bool customHash = false;
    bool customAuth = false;
    bool customIterations = false;
    
    // Parse command-line arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "-e" && i + 1 < argc) {
            encryptMode = true;
            inputFile = argv[++i];
        } else if (arg == "-d" && i + 1 < argc) {
            decryptMode = true;
            inputFile = argv[++i];
        } else if (arg == "-o" && i + 1 < argc) {
            outputFile = argv[++i];
        } else if (arg == "-r") {
            recursive = true;
        } else if (arg == "-D" && i + 1 < argc) {
            dirMode = true;
            inputDir = argv[++i];
        } else if (arg == "-p" && i + 1 < argc) {
            password = argv[++i];
        } else if (arg == "--rounds" && i + 1 < argc) {
            customRounds = true;
            config.numRounds = std::stoi(argv[++i]);
        } else if (arg == "--hash" && i + 1 < argc) {
            customHash = true;
            std::string hashType = argv[++i];
            if (hashType == "sha256" || hashType == "SHA256") {
                config.hashAlgo = HashAlgorithm::SHA256;
            } else if (hashType == "sha512" || hashType == "SHA512") {
                config.hashAlgo = HashAlgorithm::SHA512;
            } else {
                std::cerr << "Error: Invalid hash type. Use 'sha256' or 'sha512'" << std::endl;
                return 1;
            }
        } else if (arg == "--no-auth") {
            customAuth = true;
            config.useAuthentication = false;
        } else if (arg == "--iterations" && i + 1 < argc) {
            customIterations = true;
            config.pbkdf2Iterations = std::stoul(argv[++i]);
        } else if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            printUsage(argv[0]);
            return 1;
        }
    }
    
    // Validate mode selection
    if (!encryptMode && !decryptMode) {
        std::cerr << "Error: Must specify -e (encrypt) or -d (decrypt)" << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    
    if (encryptMode && decryptMode) {
        std::cerr << "Error: Cannot specify both -e and -d" << std::endl;
        return 1;
    }
    
    if (inputFile.empty() && inputDir.empty()) {
        std::cerr << "Error: Must specify input file (-e/-d) or directory (-D)" << std::endl;
        printUsage(argv[0]);
        return 1;
    }
    
    // Get password if not provided
    if (password.empty()) {
        password = readPassword();
        if (password.empty()) {
            std::cerr << "Error: Password cannot be empty" << std::endl;
            return 1;
        }
    }
    
    // Determine output file if not specified
    if (outputFile.empty()) {
        if (!inputFile.empty()) {
            if (encryptMode) {
                outputFile = inputFile + ".enc";
            } else {
                outputFile = inputFile;
                if (outputFile.size() > 4 && 
                    outputFile.substr(outputFile.size() - 4) == ".enc") {
                    outputFile = outputFile.substr(0, outputFile.size() - 4);
                } else {
                    outputFile += ".dec";
                }
            }
        }
    }
    
    try {
        if (!inputFile.empty()) {
            // Single file mode
            if (encryptMode) {
                std::cout << "Encrypting: " << inputFile << std::endl;
                encryptFile(inputFile, outputFile, password, config);
            } else {
                std::cout << "Decrypting: " << inputFile << std::endl;
                decryptFile(inputFile, outputFile, password, config);
            }
            std::cout << "Output: " << outputFile << std::endl;
            std::cout << "Success!" << std::endl;
        } else if (!inputDir.empty()) {
            // Directory mode
            if (!fs::exists(inputDir)) {
                std::cerr << "Error: Directory does not exist: " << inputDir << std::endl;
                return 1;
            }
            
            std::cout << (encryptMode ? "Encrypting" : "Decrypting") 
                      << " directory: " << inputDir << std::endl;
            
            size_t count = processDirectory(inputDir, password, encryptMode, recursive, config);
            
            std::cout << "Processed " << count << " file(s)" << std::endl;
            std::cout << "Success!" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
