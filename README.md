# 🔐 DES Encryption and Decryption in C++

### By Tahim Bhuiya

This is a **C++ implementation** of the **Data Encryption Standard (DES)** algorithm, which encrypts and decrypts 64-bit plaintext using a 64-bit symmetric key.

---

## 📜 Overview

DES (Data Encryption Standard) is a symmetric-key algorithm that encrypts data in fixed-size blocks of 64 bits. This project simulates DES by:
- Taking a **64-bit plaintext** (8 characters)
- Taking a **64-bit key** (8 characters)
- Generating 16 round keys from the main key
- Performing 16 rounds of encryption/decryption
- Displaying both encrypted and decrypted output

---

## ▶️ Usage

1. Compile the C++ code:
   ```bash
   g++ -std=c++11 -o des des.cpp
   ```
2. Run the compiled program:
   ```bash
   ./des
   ```
3. Enter the **plaintext** (exactly 8 characters).
4. Enter the **key** (exactly 8 characters).
5. The program will output:
   - Encrypted ciphertext in binary
   - Decrypted text

---

## 🧠 Code Description

### `generate_keys()`
Generates 16 48-bit round keys from the 64-bit user-provided key.  
- Applies **Permuted Choice 1 (PC-1)** to compress to 56 bits.
- Performs **left circular shifts** according to a predefined schedule.
- Applies **Permuted Choice 2 (PC-2)** to compress to 48 bits.

---

### `encrypt(plain: bitset)`
Encrypts a 64-bit plaintext using the DES algorithm.  
- Applies **Initial Permutation (IP)**.
- Splits the block into left and right halves.
- Performs 16 rounds of substitution and permutation using `f()` and round keys.
- Applies **Final Permutation (IP⁻¹)**.

---

### `decrypt(cipher: bitset)`
Decrypts a 64-bit ciphertext by reversing the encryption steps.  
- Uses the same `f()` function.
- Applies round keys in **reverse order**.

---

### `char_to_bitset(s: str)`
Converts an 8-character string to a 64-bit binary representation using C++ bit manipulation.

---

### `bitset_to_string(bit: bitset)`
Converts a 64-bit binary representation back to a readable 8-character string.

---

### `f(r: bitset[32], k: bitset[48])`
The **DES round function**.  
- Expands 32-bit `r` to 48 bits using the **E-table**.
- XORs with subkey `k`.
- Substitutes using the 8 **S-boxes**.
- Permutes the result using the **P-box**.

---

### `left_shift(k: bitset[28], shift: int)`
Performs a **left circular shift** on a 28-bit binary value.

---

## 🧩 Key Tables Used

| Table      | Purpose                           |
|------------|------------------------------------|
| `IP`       | Initial Permutation (plaintext)    |
| `IP⁻¹`     | Final Permutation (ciphertext)     |
| `PC-1`     | Permuted Choice 1 (key reduction)  |
| `PC-2`     | Permuted Choice 2 (key compression)|
| `E`        | Expansion of right half (32 → 48)  |
| `S-boxes`  | Substitution (6-bit → 4-bit)       |
| `P`        | Permutation (after S-box output)   |
| `Shift`    | Rotation schedule for round keys   |

---

## 🧪 Example Output

```
Enter the plaintext (8 characters): 12345678
Enter the key (8 characters): 12345678
Cipher Text: 011011011001...
Decrypted Plain Text: 12345678
```

---

## 📦 Requirements
- C++11 compatible compiler
- No external libraries needed (pure C++ implementation)

---

## ✅ Notes
- The input must be **exactly 8 characters** long for both plaintext and key.
- The script uses `std::bitset` for binary operations.

---

## 📣 Credits
Developed by **Tahim Bhuiya**  
Assignment 2 - DES Implementation (C++)

---

## 🎉 Enjoy!