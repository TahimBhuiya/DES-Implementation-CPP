//Tahim Bhuiya

#include <iostream>
#include <bitset>
#include <string>
using namespace std;

bitset<64> key;                // 64-bit main key used for both encryption and decryption.
bitset<48> sub_key[16];        // Stores 16 round-specific 48-bit subkeys generated from the main key.

// Initial Permutation (IP) table
// Rearranges the 64-bit plaintext input before the first round of DES.
// The order of bits is critical to DES diffusion properties.
int ip[] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9,  1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

// Final Permutation (IP^-1) table
// Applied after the 16 DES rounds; reverses the effect of the initial permutation (IP).
// Restores the bit order to its final output format (ciphertext or plaintext).
int ip_1[] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};


// Permuted Choice 1 (PC-1) table:
// This table is used to permute the original 64-bit key by selecting 
// 56 bits in a specific order, discarding the 8 parity bits (positions 8, 16, ..., 64).
// The result is split into two 28-bit halves (C and D) for further processing.
int pc_1[] = {
    57, 49, 41, 33, 25, 17, 9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

// Permuted Choice 2 (PC-2) table:
// After rotating the halves from PC-1, this table selects 48 out of the 56 bits 
// to form a subkey for each of the 16 DES rounds. The selection is done 
// according to the specified permutation order.
int pc_2[] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};



// Number of left shifts for each round key
int shift_bits[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// Expansion table for the round function
int e[] = {32,  1,  2,  3,  4,  5,
           4,  5,  6,  7,  8,  9,
           8,  9, 10, 11, 12, 13,
          12, 13, 14, 15, 16, 17,
          16, 17, 18, 19, 20, 21,
          20, 21, 22, 23, 24, 25,
          24, 25, 26, 27, 28, 29,
          28, 29, 30, 31, 32,  1};

// S-boxes for the round function
int s_box[8][4][16] = {
    // S1
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    // S2
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    // S3
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    // S4
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    // S5
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    // S6
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    // S7
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    // S8
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};

// Permutation table for the round function
int p[] = {16,  7, 20, 21,
           29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2,  8, 24, 14,
           32, 27,  3,  9,
           19, 13, 30,  6,
           22, 11,  4, 25 };

// Function to compute the round function
bitset<32> f(bitset<32> r, bitset<48> k)
{
    bitset<48> expand_r;

    // Expansion permutation
    for(int i = 0; i < 48; ++i)
        expand_r[47 - i] = r[32 - e[i]];

    // XOR with round key
    expand_r = expand_r ^ k;

    bitset<32> output;
    int x = 0;
    // Applying S-box substitution
    for(int i = 0; i < 48; i = i + 6)
    {
        int row = expand_r[47 - i] * 2 + expand_r[47 - i - 5];
        int col = expand_r[47 - i - 1] * 8 + expand_r[47 - i - 2] * 4 + expand_r[47 - i - 3] * 2 + expand_r[47 - i - 4];
        int num = s_box[i / 6][row][col];
        bitset<4> binary(num);
        output[31 - x] = binary[3];
        output[31 - x - 1] = binary[2];
        output[31 - x - 2] = binary[1];
        output[31 - x - 3] = binary[0];
        x += 4;
    }

    bitset<32> temp = output;
    // Permutation
    for(int i = 0; i < 32; ++i)
        output[31 - i] = temp[32 - p[i]];

    return output;
}

// Function to perform left circular shift on the key
bitset<28> left_shift(bitset<28> k, int shift)
{
    bitset<28> temp = k;
    for(int i = 27; i >= 0; --i)
    {
        if(i - shift < 0)
            k[i] = temp[i - shift + 28];
        else
            k[i] = temp[i - shift];
    }
    return k;
}

void generate_keys() 
{
    bitset<56> key_real;    
    bitset<28> left;       
    bitset<28> right;      
    bitset<48> key_compress;

   
    for (int i = 0; i < 56; ++i)
        key_real[55 - i] = key[64 - pc_1[i]];


    for(int round = 0; round < 16; ++round) 
    {
        for(int i = 28; i < 56; ++i)
            left[i - 28] = key_real[i];
        for(int i = 0; i < 28; ++i)
            right[i] = key_real[i];
        
        left = left_shift(left, shift_bits[round]);
        right = left_shift(right, shift_bits[round]);
        
        for(int i = 28; i < 56; ++i)
            key_real[i] = left[i - 28];
        for(int i = 0; i < 28; ++i)
            key_real[i] = right[i];
        
        for(int i = 0; i < 48; ++i)
            key_compress[47 - i] = key_real[56 - pc_2[i]];
        
        sub_key[round] = key_compress;
    }
}

// Function to convert a character array to a bitset
bitset<64> char_to_bitset(const char s[8])
{
    bitset<64> bits;
    for(int i = 0; i < 8; ++i)
        for(int j = 0; j < 8; ++j)
            bits[i * 8 + j] = ((s[i] >> j) & 1);
    return bits;
}

// Function to convert a bitset to a string
string bitset_to_string(bitset<64> bit){
    string res;
    for(int i = 0; i < 8; ++i){
        char c = 0x00;
        for(int j = 7; j >= 0; j--){
            c = c + bit[i * 8 + j];     
            if(j != 0) c = c * 2;   // Left shift
        }       
        res.push_back(c);
    }
    return res;
}

// Function to encrypt the plaintext using DES algorithm
bitset<64> encrypt(bitset<64>& plain)
{
    bitset<64> cipher;     // Create a bitset to store the encrypted ciphertext
    bitset<64> current_bits;
    bitset<32> left;
    bitset<32> right;
    bitset<32> new_left;

    // Initial permutation of the plaintext
    for(int i = 0; i < 64; ++i)
        current_bits[63 - i] = plain[64 - ip[i]];

    // Split the plaintext into left and right halves
    for(int i = 32; i < 64; ++i)
        left[i - 32] = current_bits[i];
    for(int i = 0; i < 32; ++i)
        right[i] = current_bits[i];
    
    // Perform 16 rounds of DES encryption
    for(int round = 0; round < 16; ++round)
    {
        // Save the previous left half
        new_left = right;
        // Compute the new right half using the round function and subkey
        right = left ^ f(right, sub_key[round]);
        // Set the new left half to the previous right half
        left = new_left;
    }
    
    // Combine the left and right halves
    for(int i = 0; i < 32; ++i)
        cipher[i] = left[i];
    for(int i = 32; i < 64; ++i)
        cipher[i] = right[i - 32];

    // Final permutation of the ciphertext
    current_bits = cipher;
    for(int i = 0; i < 64; ++i)
        cipher[63 - i] = current_bits[64 - ip_1[i]];

    return cipher;
}

// Function to decrypt the ciphertext using DES algorithm
bitset<64> decrypt(bitset<64>& cipher)
{
    bitset<64> plain;      // Create a bitset to store the decrypted plaintext
    bitset<64> current_bits;
    bitset<32> left;
    bitset<32> right;
    bitset<32> new_left;

    // Initial permutation of the ciphertext
    for(int i = 0; i < 64; ++i)
        current_bits[63 - i] = cipher[64 - ip[i]];

    // Split the ciphertext into left and right halves
    for(int i = 32; i < 64; ++i)
        left[i - 32] = current_bits[i];
    for(int i = 0; i < 32; ++i)
        right[i] = current_bits[i];

    // Perform 16 rounds of DES decryption
    for(int round = 0; round < 16; ++round)
    {
        // Save the previous left half
        new_left = right;
        // Compute the new right half using the round function and subkey in reverse order
        right = left ^ f(right, sub_key[15 - round]);
        // Set the new left half to the previous right half
        left = new_left;
    }

    // Combine the left and right halves
    for(int i = 0; i < 32; ++i)
        plain[i] = left[i];
    for(int i = 32; i < 64; ++i)
        plain[i] = right[i - 32];

    // Final permutation of the plaintext
    current_bits = plain;
    for(int i = 0; i < 64; ++i)
        plain[63 - i] = current_bits[64 - ip_1[i]];

    return plain;
}

int main() {
    string plain_text, key_text;
    cout << "Enter the plaintext (Must be 64 bits): ";
    cin >> plain_text;
    cout << "Enter the key (Must be 64 bits): ";
    cin >> key_text;

    if (plain_text.length() != 8 || key_text.length() != 8) {
        cout << "Error: Plaintext and key must be 64 bits each." << endl;
        return 1;
    }

    bitset<64> plain = char_to_bitset(plain_text.c_str());
    key = char_to_bitset(key_text.c_str());

    generate_keys();   // Generate subkeys for encryption and decryption

    bitset<64> cipher = encrypt(plain); // Encrypt the plaintext
    cout << "Cipher Text: " << cipher << endl;

    bitset<64> decrypted_plain = decrypt(cipher); // Decrypt the ciphertext
    cout << "Decrypted Plain Text: " << bitset_to_string(decrypted_plain) << endl;

    return 0;
}