# Lofer Cipher

A symmetric-key block cipher implementation using a Substitution-Permutation Network (SPN) design.

## Overview

Lofer is a custom cipher that combines:
- **Key-dependent S-boxes**: Generated using Fisher-Yates shuffle for bijective substitution
- **Affine permutations**: Position-based diffusion layer
- **Multiple rounds**: Variable round count derived from the password

## Features

- Byte-oriented operation (8-bit elements)
- Salt-based key derivation for semantic security
- Variable round count (8-32 rounds)
- Bijective S-boxes ensuring perfect decryption

## Usage

### Command Line

```bash
# Encrypt a file
./lofer -e input.txt -o encrypted.bin -p "your_password"

# Decrypt a file
./lofer -d encrypted.bin -o decrypted.txt -p "your_password"
```

### Options

| Option | Description |
|--------|-------------|
| `-e <file>` | Encrypt the specified file |
| `-d <file>` | Decrypt the specified file |
| `-o <output>` | Output file path |
| `-p <password>` | Encryption/decryption password |
| `-h` | Show help message |

## Algorithm Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| SALT_LEN | 16 bytes | Random salt for key derivation |
| R_MIN | 8 | Minimum number of rounds |
| R_MAX | 32 | Maximum number of rounds |
| M | 256 | Alphabet size (2^8 for bytes) |

## Building

```bash
g++ -std=c++17 -O2 -o lofer lofer.cpp
g++ -std=c++17 -O2 -o test_runner test.cpp
```

## File Format

Encrypted files have the following structure:

```
+---------------------+-------------------+
| Salt (16 bytes)     | Ciphertext (L bytes) |
+---------------------+-------------------+
```

Where L is the plaintext length in bytes.
