#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <random>
#include <sstream>
#include <filesystem>

namespace fs = std::filesystem;

// Algorithm Parameters
constexpr size_t SALT_LEN = 128;
constexpr int R_MIN = 1;
constexpr int R_MAX = std::pow(1024, 2);
constexpr size_t M = 256;  // Alphabet size (2^8 for bytes)

using Element = uint8_t;
using Byte = uint8_t;

// Simple KDF
class SimpleKDF {
public:
    static std::vector<Byte> derive(const std::string& password, const std::vector<Byte>& salt, size_t outputLen) {
        std::vector<Byte> result;
        std::vector<Byte> data(password.begin(), password.end());
        data.insert(data.end(), salt.begin(), salt.end());
        
        for (size_t block = 0; block < (outputLen + 31) / 32; ++block) {
            std::vector<Byte> blockData = data;
            blockData.push_back(static_cast<Byte>(block & 0xFF));
            blockData.push_back(static_cast<Byte>((block >> 8) & 0xFF));
            
            auto hash = mix(blockData);
            result.insert(result.end(), hash.begin(), hash.end());
        }
        
        result.resize(outputLen);
        return result;
    }
    
private:
    static std::vector<Byte> mix(const std::vector<Byte>& input) {
        uint32_t state[8] = {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
        
        for (size_t i = 0; i < input.size(); ++i) {
            state[i % 8] ^= static_cast<uint32_t>(input[i]) << ((i % 4) * 8);
            state[(i + 1) % 8] += state[i % 8];
            state[(i + 2) % 8] ^= state[(i + 1) % 8] >> 17;
        }
        
        for (int r = 0; r < 8; ++r) {
            for (int i = 0; i < 8; ++i) {
                state[i] ^= rotl(state[(i + 7) % 8], 7);
                state[i] += rotl(state[(i + 1) % 8], 13);
                state[i] ^= rotl(state[(i + 2) % 8], 17);
            }
        }
        
        std::vector<Byte> output(32);
        for (int i = 0; i < 8; ++i) {
            output[i * 4 + 0] = state[i] & 0xFF;
            output[i * 4 + 1] = (state[i] >> 8) & 0xFF;
            output[i * 4 + 2] = (state[i] >> 16) & 0xFF;
            output[i * 4 + 3] = (state[i] >> 24) & 0xFF;
        }
        
        return output;
    }
    
    static uint32_t rotl(uint32_t x, int k) {
        return (x << k) | (x >> (32 - k));
    }
};

// PRF
class PRF {
public:
    static std::vector<Byte> compute(const std::vector<Byte>& key, const std::string& context) {
        std::vector<Byte> data = key;
        data.insert(data.end(), context.begin(), context.end());
        return SimpleKDF::derive(std::string(data.begin(), data.end()), {}, 32);
    }
};

// PRNG class
class PRNG {
public:
    void seed(const std::vector<Byte>& seedData) {
        uint32_t s[4] = {0};
        for (size_t i = 0; i < seedData.size() && i < 16; ++i) {
            s[i % 4] = (s[i % 4] << 8) | seedData[i];
        }
        state[0] = s[0] ^ 0x12345678;
        state[1] = s[1] ^ 0x9abcdef0;
        state[2] = s[2] ^ 0x13579bdf;
        state[3] = s[3] ^ 0x2468ace0;
    }
    
    uint32_t next() {
        uint32_t t = state[3];
        uint32_t s = state[0];
        state[3] = state[2];
        state[2] = state[1];
        state[1] = s;
        t ^= t << 11;
        t ^= t >> 8;
        state[0] = t ^ s ^ (s >> 19);
        return state[0];
    }
    
private:
    uint32_t state[4];
};

uint32_t gcd(uint32_t a, uint32_t b) {
    while (b) {
        uint32_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

struct RoundParams {
    std::vector<Element> S_r;
    size_t a, b;
    size_t a_inv, b_inv;
    std::vector<Byte> prngSeed;
};

std::vector<Element> generateSubstitutionTable(const std::vector<Byte>& roundSeed) {
    PRNG prng;
    prng.seed(roundSeed);
    
    // Create identity permutation first
    std::vector<Element> S(M);
    for (size_t i = 0; i < M; ++i) {
        S[i] = static_cast<Element>(i);
    }
    
    // Fisher-Yates shuffle to create a proper bijective permutation
    for (size_t i = M - 1; i > 0; --i) {
        size_t j = prng.next() % (i + 1);
        Element tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }
    
    return S;
}

void generatePermutation(const std::vector<Byte>& roundSeed, size_t L, size_t& a, size_t& b) {
    PRNG prng;
    prng.seed(roundSeed);
    
    do {
        a = prng.next() % L;
        if (a == 0) a = 1;
    } while (gcd(static_cast<uint32_t>(a), static_cast<uint32_t>(L)) != 1);
    
    b = prng.next() % L;
}

void deriveParameters(const std::string& password, const std::vector<Byte>& salt, 
                      int& R, std::vector<RoundParams>& params) {
    auto masterKey = SimpleKDF::derive(password, salt, 64);
    R = R_MIN + (masterKey[0] % (R_MAX - R_MIN + 1));
    
    params.resize(R);
    
    for (int r = 1; r <= R; ++r) {
        std::ostringstream ctx;
        ctx << "round" << r << "seed";
        
        auto roundSeed = PRF::compute(masterKey, ctx.str());
        params[r-1].S_r = generateSubstitutionTable(roundSeed);
        params[r-1].prngSeed = PRF::compute(roundSeed, "prng");
    }
}

void instantiatePermutations(size_t L, std::vector<RoundParams>& params) {
    for (auto& p : params) {
        generatePermutation(p.prngSeed, L, p.a, p.b);
        
        // Compute modular inverse using extended Euclidean algorithm
        int32_t m0 = static_cast<int32_t>(L);
        int32_t y = 0, x = 1;
        int32_t aa = static_cast<int32_t>(p.a);
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
        p.a_inv = static_cast<size_t>(x);
        p.b_inv = (L - (p.a_inv * p.b) % L) % L;
    }
}

// Substitution-Permutation Network encryption
std::vector<Byte> encrypt(const std::vector<Byte>& plaintext, const std::string& password) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    std::vector<Byte> salt(SALT_LEN);
    for (size_t i = 0; i < SALT_LEN; ++i) {
        salt[i] = static_cast<Byte>(dis(gen));
    }
    
    int R;
    std::vector<RoundParams> params;
    deriveParameters(password, salt, R, params);
    
    size_t L = plaintext.size();
    
    // Handle empty input
    if (L == 0) {
        return salt;
    }
    
    std::vector<Element> state(plaintext.begin(), plaintext.end());
    
    instantiatePermutations(L, params);
    
    for (int r = 0; r < R; ++r) {
        // Substitution step: apply S-box lookup
        for (size_t i = 0; i < L; ++i) {
            state[i] = params[r].S_r[state[i]];
        }
        
        // Permutation step: affine transformation
        if (L > 1) {
            std::vector<Element> newState(L);
            for (size_t i = 0; i < L; ++i) {
                size_t newPos = (params[r].a * i + params[r].b) % L;
                newState[newPos] = state[i];
            }
            state = newState;
        }
    }
    
    std::vector<Byte> result;
    result.reserve(SALT_LEN + L);
    result.insert(result.end(), salt.begin(), salt.end());
    result.insert(result.end(), state.begin(), state.end());
    
    return result;
}

std::vector<Byte> decrypt(const std::vector<Byte>& encrypted, const std::string& password) {
    if (encrypted.size() < SALT_LEN) {
        throw std::runtime_error("Invalid input: too short");
    }
    
    std::vector<Byte> salt(encrypted.begin(), encrypted.begin() + SALT_LEN);
    std::vector<Byte> ciphertext(encrypted.begin() + SALT_LEN, encrypted.end());
    size_t L = ciphertext.size();
    
    if (L == 0) {
        return std::vector<Byte>();
    }
    
    int R;
    std::vector<RoundParams> params;
    deriveParameters(password, salt, R, params);
    
    instantiatePermutations(L, params);

    std::vector<std::vector<Element>> invS(R);
    for (int r = 0; r < R; ++r) {
        invS[r].resize(M);
        for (size_t x = 0; x < M; ++x) {
            Element c = params[r].S_r[x];
            invS[r][c] = static_cast<Element>(x);
        }
    }
    
    std::vector<Element> state(ciphertext.begin(), ciphertext.end());
    
    for (int r = R - 1; r >= 0; --r) {
        if (L > 1) {
            std::vector<Element> newState(L);
            for (size_t j = 0; j < L; ++j) {
                size_t origPos = (params[r].a_inv * j + params[r].b_inv) % L;
                newState[origPos] = state[j];
            }
            state = newState;
        }
        for (size_t i = 0; i < L; ++i) {
            Element c = state[i];
            state[i] = invS[r][c];
        }
    }
    
    return std::vector<Byte>(state.begin(), state.end());
}

std::vector<Byte> readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    std::vector<Byte> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file: " + path);
    }
    
    return buffer;
}

void writeFile(const std::string& path, const std::vector<Byte>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot create file: " + path);
    }
    
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

void printUsage(const char* progName) {
    std::cout << "Usage: " << progName << " [options]\n"
              << "Options:\n"
              << "  -e <file>     Encrypt file\n"
              << "  -d <file>     Decrypt file\n"
              << "  -o <output>   Output file\n"
              << "  -r            Recursive mode\n"
              << "  -D <dir>      Process directory\n"
              << "  -R <rounds>   Set number of rounds (optional)\n"
              << "  -p <password> Password (or will prompt)\n"
              << "  -h            Show this help\n";
}

int main(int argc, char* argv[]) {
    std::string inputFile;
    std::string outputFile;
    std::string inputDir;
    std::string password;
    bool encryptMode = false;
    bool decryptMode = false;
    bool recursive = false;
    bool dirMode = false;
    
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
        } else if (arg == "-R" && i + 1 < argc) {
            // Custom rounds not implemented in this version
        } else if (arg == "-p" && i + 1 < argc) {
            password = argv[++i];
        } else if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
    }
    
    if (!encryptMode && !decryptMode) {
        std::cerr << "Error: Must specify -e (encrypt) or -d (decrypt)\n";
        printUsage(argv[0]);
        return 1;
    }
    
    if (encryptMode && decryptMode) {
        std::cerr << "Error: Cannot specify both -e and -d\n";
        return 1;
    }
    
    if (inputFile.empty() && inputDir.empty()) {
        std::cerr << "Error: Must specify input file or directory\n";
        printUsage(argv[0]);
        return 1;
    }
    
    if (password.empty()) {
        std::cout << "Enter password: ";
        std::getline(std::cin, password);
        if (password.empty()) {
            std::cerr << "Error: Password cannot be empty\n";
            return 1;
        }
    }
    
    if (outputFile.empty()) {
        if (encryptMode && !inputFile.empty()) {
            outputFile = inputFile + ".enc";
        } else if (decryptMode && !inputFile.empty()) {
            outputFile = inputFile;
            if (outputFile.size() > 4 && outputFile.substr(outputFile.size() - 4) == ".enc") {
                outputFile = outputFile.substr(0, outputFile.size() - 4);
            } else {
                outputFile += ".dec";
            }
        }
    }
    
    try {
        if (!inputFile.empty()) {
            auto inputData = readFile(inputFile);
            std::vector<Byte> resultData;
            
            if (encryptMode) {
                std::cout << "Encrypting: " << inputFile << std::endl;
                resultData = encrypt(inputData, password);
            } else {
                std::cout << "Decrypting: " << inputFile << std::endl;
                resultData = decrypt(inputData, password);
            }
            
            writeFile(outputFile, resultData);
            std::cout << "Output: " << outputFile << std::endl;
            std::cout << "Success!" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
