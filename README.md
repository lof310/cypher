# Lofer Cipher

A symmetric-key block cipher using Substitution-Permutation Network (SPN) design.

## Build & Run

```bash
g++ -std=c++17 -O3 -march=native -I include -o lofer src/main.cpp
```

## Usage

```bash
# Basic encrypt/decrypt
./lofer -e input.txt -p "password"
./lofer -d input.txt.enc -p "password"

# With options
./lofer -e data.bin --rounds 24 --hash sha512 --iterations 200000 -p "password"
./lofer -D ./docs -r -p "password"  # Process directory recursively

# Show all options
./lofer --help
```

### Command-line Options

| Option | Description |
|--------|-------------|
| `-e <file>` | Encrypt file |
| `-d <file>` | Decrypt file |
| `-o <output>` | Output path |
| `-D <dir>` | Process directory |
| `-r` | Recursive mode |
| `-p <password>` | Password (prompts if omitted) |
| `--rounds <N>` | SPN rounds: 8-32 (default: 16) |
| `--hash <type>` | sha256 or sha512 (default: sha256) |
| `--iterations <N>` | PBKDF2 iterations (default: 100000) |
| `--no-auth` | Disable HMAC (not recommended) |

## API Usage

```cpp
#include "cipher.hpp"
using namespace lofer;

// Default configuration
auto encrypted = encrypt(plaintext, password);
auto decrypted = decrypt(encrypted, password);

// Custom configuration
CipherConfig config;
config.hashAlgo = HashAlgorithm::SHA512;
config.numRounds = 24;
config.pbkdf2Iterations = 200000;
config.useAuthentication = true;

auto encrypted = encrypt(plaintext, password, config);
```

## Algorithm

1. Generate random 16-byte salt
2. Derive keys via PBKDF2-HMAC-SHA256/512
3. For each round: S-box substitution → affine permutation
4. Compute HMAC over ciphertext (Encrypt-then-MAC)
5. Output: `salt || ciphertext || HMAC`

## File Format

```
+----------+------------+----------+
| Salt     | Ciphertext | HMAC     |
| 16 bytes | L bytes    | 32 bytes |
+----------+------------+----------+
```