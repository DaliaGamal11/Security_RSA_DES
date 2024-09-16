#ifndef DES_H_INCLUDED
#define DES_H_INCLUDED

#include <iostream>
#include <bitset>
#include <vector>
#include <fstream>
#include <sstream>
#include <string>
#include <cstring>
#include <regex>
#include <algorithm>

using namespace std;

class DES {
    private:
        // Initial Permutation Table
        static int IP[];
        // Final Permutation Table
        static int FP[];
        // Expansion Permutation Table
        static int EP[];
        // Straight Permutation Table
        static int P[];
        // S-Boxes
        static int sbox[8][4][16];
        // Key Permutation Table 1 (PC-1)
        static int PC1[];
        // Key Permutation Table 2 (PC-2)
        static int PC2[];
        // Number of Left Shifts for Each Round of Key Generation
        static int shifts[];

        static string permute(const string&, int[], int);
        static string bitwiseXOR(const string&, const string&);
        static string applySBox(const string&);
        static vector<string> generateSubKeys(string);
        static string encryptBlock(string, vector<string>&);
        static string decryptBlock(string, vector<string>&);
        static string binaryToBase64(const string&);
        static string stringToBinary(const string&);
        static string binaryToString(const string&);
        static string padTo64Bits(const string&);
        static string extractBinaryStringFromFile(const string&);
        static string readFromFile(const string&);
        static void writeToFile(const string&, const string&);
        static void appendToFile(const string&, const string&);
    public:
        static string DES_Encryption(const string&, const string&);
        static string DES_Decryption(const string&, const string&);
};

int DES::IP[] = {58, 50, 42, 34, 26, 18, 10, 2,
                 60, 52, 44, 36, 28, 20, 12, 4,
                 62, 54, 46, 38, 30, 22, 14, 6,
                 64, 56, 48, 40, 32, 24, 16, 8,
                 57, 49, 41, 33, 25, 17,  9, 1,
                 59, 51, 43, 35, 27, 19, 11, 3,
                 61, 53, 45, 37, 29, 21, 13, 5,
                 63, 55, 47, 39, 31, 23, 15, 7};

int DES::FP[] = {40, 8, 48, 16, 56, 24, 64, 32,
                 39, 7, 47, 15, 55, 23, 63, 31,
                 38, 6, 46, 14, 54, 22, 62, 30,
                 37, 5, 45, 13, 53, 21, 61, 29,
                 36, 4, 44, 12, 52, 20, 60, 28,
                 35, 3, 43, 11, 51, 19, 59, 27,
                 34, 2, 42, 10, 50, 18, 58, 26,
                 33, 1, 41,  9, 49, 17, 57, 25};

int DES::EP[] = {32,  1,  2,  3,  4,  5,
                  4,  5,  6,  7,  8,  9,
                  8,  9, 10, 11, 12, 13,
                 12, 13, 14, 15, 16, 17,
                 16, 17, 18, 19, 20, 21,
                 20, 21, 22, 23, 24, 25,
                 24, 25, 26, 27, 28, 29,
                 28, 29, 30, 31, 32,  1};

int DES::P[] = {16, 7, 20,  21, 29, 12, 28, 17,
                 1, 15, 23, 26,  5, 18, 31, 10,
                 2,  8, 24, 14, 32, 27,  3,  9,
                19, 13, 30,  6, 22, 11,  4, 25};

int DES::sbox[8][4][16] = {
         {
             // S1
             {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
             {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
             {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
             {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
         },
         {
             // S2
             {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
             {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
             {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
             {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
         },
         {
             // S3
             {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
             {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
             {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
             {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
         },
         {
             // S4
             {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
             {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
             {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
             {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
         },
         {
             // S5
             {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
             {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
             {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
             {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
         },
         {
             // S6
             {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
             {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
             {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
             {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
         },
         {
             // S7
             {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
             {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
             {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
             {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
         },
         {
             // S8
             {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
             {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
             {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
             {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
         }
};

int DES::PC1[] = {57, 49, 41, 33, 25, 17,  9,
                   1, 58, 50, 42, 34, 26, 18,
                   10,  2, 59, 51, 43, 35, 27,
                   19, 11,  3, 60, 52, 44, 36,
                   63, 55, 47, 39, 31, 23, 15,
                    7, 62, 54, 46, 38, 30, 22,
                    14, 6, 61, 53, 45, 37, 29,
                    21, 13, 5, 28, 20, 12,  4};

int DES::PC2[] = {14, 17, 11, 24,  1,  5,  3, 28,
                  15,  6, 21, 10, 23, 19, 12,  4,
                  26,  8, 16,  7, 27, 20, 13,  2,
                  41, 52, 31, 37, 47, 55, 30, 40,
                  51, 45, 33, 48, 44, 49, 39, 56,
                  34, 53, 46, 42, 50, 36, 29, 32};

int DES::shifts[] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

// Encrypts Binary Plain Text Using The DES Encryption Algorithm
string DES::DES_Encryption(const string& plaintextFilePath, const string& keyFilePath) {
    // Read plaintext and key from files
    string plaintext = readFromFile(plaintextFilePath);
    string key = readFromFile(keyFilePath);

    // Convert plaintext and key to binary using stringToBinary
    string binaryPlainText = stringToBinary(plaintext);
    string binaryKey = stringToBinary(key);

    // Pad binary plaintext and binary key to ensure they are divisible by 64
    binaryPlainText = padTo64Bits(binaryPlainText);
    binaryKey = padTo64Bits(binaryKey);

    // Generate 16 SubKeys, Each of Which is 48 bits long
    vector<string> keys = generateSubKeys(binaryKey);

    // The Binary Plain Text is Splited into Blocks, Each of Which is 64 bits long
    vector<string> blocks;
    for (int i = 0; i < binaryPlainText.length(); i += 64) {
        blocks.push_back(binaryPlainText.substr(i, 64));
    }

    // Each Block is Encrypted Using The Generated 48-bit SubKeys and Appended to The Encrypted Text
    string encryptedText;
    for (int i = 0; i < blocks.size(); ++i) {
        const string& block = blocks[i];
        encryptedText += encryptBlock(block, keys);
    }

    writeToFile("ciphertext.txt", "Binary: ");
    appendToFile("ciphertext.txt", encryptedText);
    appendToFile("ciphertext.txt", "\n");
    appendToFile("ciphertext.txt", "Base64: ");
    appendToFile("ciphertext.txt", binaryToBase64(encryptedText));
    cout << "Encryption Is Completed. Cipher Text Is Written To ciphertext.txt" << endl;

    // Return The Encrypted Text (Cipher Text)
    return encryptedText;
}

string DES::DES_Decryption(const string& ciphertextFilePath, const string& keyFilePath) {
    // Read ciphertext and key from files
    string binaryCiphertext = extractBinaryStringFromFile(ciphertextFilePath);

    // Read key from file
    string key = readFromFile(keyFilePath);

    // Convert key to binary using stringToBinary
    string binaryKey = stringToBinary(key);
    binaryKey = padTo64Bits(binaryKey);

    // Generate 16 SubKeys, Each of Which is 48 bits long
    vector<string> keys = generateSubKeys(binaryKey);

    // The Binary Ciphertext is Splited into Blocks, Each of Which is 64 bits long
    vector<string> blocks;
    for (int i = 0; i < binaryCiphertext.length(); i += 64) {
        blocks.push_back(binaryCiphertext.substr(i, 64));
    }

    // Each Block is Decrypted Using The Generated 48-bit SubKeys and Appended to The Decrypted Text
    string decryptedText;
    for (int i = 0; i < blocks.size(); ++i) {
        const string& block = blocks[i];
        decryptedText += decryptBlock(block, keys);
    }

    writeToFile("decrypted.txt", binaryToString(decryptedText));
    cout << "Decryption Is Completed. Decrypted Text (Original Plain Text) Is Written To decrypted.txt" << endl;

    // Return The Decrypted Text (Plain Text)
    return decryptedText;
}

string DES::permute(const string& text, int permutationTable[], int tableSize) {
    // An Empty String is Initialized to Store The Result of Permutation
    string result;

    // Iterate Through Each Element of the Permutation Table
    for (int i = 0; i < tableSize; ++i) {
        // Append The Character From The Input Text at The Index specified by The Permutation Table, After Subtracting 1 to Adjust for 0-based Indexing
        result += text[permutationTable[i] - 1];
    }

    // Return The Resulting String After Permutation
    return result;
}

string DES::bitwiseXOR(const string& str1, const string& str2) {
    string result;
    for (size_t i = 0; i < str1.length(); ++i) {
        result += ((str1[i] - '0') ^ (str2[i] - '0')) + '0';
    }
    return result;
}

string DES::applySBox(const string& input) {
    string substitutionResult;
    for (int j = 0; j < 8; ++j) {
        string chunk = input.substr(j * 6, 6);
        int row = (chunk[0] - '0') * 2 + (chunk[5] - '0');
        int col = stoi(chunk.substr(1, 4), nullptr, 2);
        substitutionResult += bitset<4>(sbox[j][row][col]).to_string();
    }
    return substitutionResult;
}

vector<string> DES::generateSubKeys(string key) {
    // The 64-bit Key is Permuted According to The PC-1 Table to Rearrange Its Bits and Reduce Its Size to 56-bit Key
    key = permute(key, PC1, 56);
    // The 56-bit Permuted Key is Divided Into Left and Right Halves, Each of Which is 28 Bits Long
    string leftHalf = key.substr(0, 28);
    string rightHalf = key.substr(28);

    // Iterate Through 16 Rounds of Key Generation
    vector<string> keys;
    for (int i = 0; i < 16; ++i) {
        int shift = shifts[i];
        // Each Half of The 56-bit Permuted Key is Circularly Shifted Left by The Specified Shift Amount for This Round
        rotate(leftHalf.begin(), leftHalf.begin() + shift, leftHalf.end());
        rotate(rightHalf.begin(), rightHalf.begin() + shift, rightHalf.end());
        // Left and Right Halves are Combine to Form The Round Key
        string roundKey = leftHalf + rightHalf;
        // Round Key is Permuted According to The PC-2 Table to Rearrange Its Bits and Reduce Its Size to 48-bit SubKey
        roundKey = permute(roundKey, PC2, 48);
        // The 48-bit SubKey is Added to The Collection of Keys
        keys.push_back(roundKey);
    }

    // Return the Generated SubKeys
    return keys;
}

string DES::encryptBlock(string block, vector<string>& keys) {
    // The 64-bit Block is Permuted According to The Initial Permutation (IP) Table
    block = permute(block, IP, 64);

    // The 64-bit Permuted Block is Divided Into Left and Right Halves, Each of Which is 32 Bits Long
    string leftHalf = block.substr(0, 32);
    string rightHalf = block.substr(32);

    // Iterate Through 16 Rounds of Encryption Using The Provided SubKeys
    for (int i = 0; i < 16; ++i) {
        // The Right Half of The Block is Expanded From 32 Bits to 48 Bits Using The Expansion Permutation (EP) Table
        string expandedRightHalf = permute(rightHalf, EP, 48);

        // Bitwise XOR is Performed Between The Expanded Right Half and The Current Round SubKey
        string XOR_Result = bitwiseXOR(expandedRightHalf, keys[i]);

        // Substitution Using The S-boxes is Applied to The XOR Result To Obtain a 32-bit Intermediate Result
        string substitutionResult = applySBox(XOR_Result);

        // The Substitution Result is Permuted Using The Permutation (P) table
        string permutationResult = permute(substitutionResult, P, 32);

        // Bitwise XOR is Performed Between The Left Half of The Block and The Permuted Substitution Result
        string newRightHalf = bitwiseXOR(leftHalf, permutationResult);

        // The Left and Right Halves of The Block are Updated for The Next Round
        leftHalf = rightHalf;
        rightHalf = newRightHalf;
    }

    // The Concatenation of The Right and Left Halves of The Block is Permuted According to The Final Permutation (FP) table
    string encryptedBlock = permute(rightHalf + leftHalf, FP, 64);

    // Return the encrypted block
    return encryptedBlock;
}

string DES::decryptBlock(string block, vector<string>& keys) {
    // The 64-bit Block is Permuted According to The Initial Permutation (IP) Table
    block = permute(block, IP, 64);

    // The 64-bit Permuted Block is Divided Into Left and Right Halves, Each of Which is 32 Bits Long
    string leftHalf = block.substr(0, 32);
    string rightHalf = block.substr(32);

    // Iterate Through 16 Rounds of Decryption Using The Provided SubKeys in Reverse Order
    for (int i = 15; i >= 0; --i) {
        // The Right Half of The Block is Expanded From 32 Bits to 48 Bits Using The Expansion Permutation (EP) Table
        string expandedRightHalf = permute(rightHalf, EP, 48);

        // Bitwise XOR is Performed Between The Expanded Right Half and The Current Round SubKey
        string XOR_Result = bitwiseXOR(expandedRightHalf, keys[i]);

        // Substitution Using The S-boxes is Applied to The XOR Result To Obtain a 32-bit Intermediate Result
        string substitutionResult = applySBox(XOR_Result);

        // The Substitution Result is Permuted Using The Permutation (P) table
        string permutationResult = permute(substitutionResult, P, 32);

        // Bitwise XOR is Performed Between The Left Half of The Block and The Permuted Substitution Result
        string newRightHalf = bitwiseXOR(leftHalf, permutationResult);

        // The Left and Right Halves of The Block are Updated for The Next Round
        leftHalf = rightHalf;
        rightHalf = newRightHalf;
    }

    // The Concatenation of The Right and Left Halves of The Block is Permuted According to The Final Permutation (FP) table
    string decryptedBlock = permute(rightHalf + leftHalf, FP, 64);

    // Return the decrypted block
    return decryptedBlock;
}

string DES::stringToBinary(const string& input) {
    string binaryString;
    for (char c : input) {
        // Convert Each Character to Its Binary Representation and Append to binaryString
        binaryString += bitset<8>(c).to_string();
    }
    return binaryString;
}

string DES::binaryToString(const string& binaryInput) {
    string result;
    for (size_t i = 0; i < binaryInput.length(); i += 8) {
        // Extract 8 Bits at A Time and Convert Them to a Character
        bitset<8> bits(binaryInput.substr(i, 8));
        char c = static_cast<char>(bits.to_ulong());
        result += c;
    }
    return result;
}

string DES::binaryToBase64(const string& binary) {
    const string base64_chars ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    string base64;
    int bits_collected = 0;
    unsigned int accumulator = 0;

    for (char c : binary) {
        accumulator = (accumulator << 1) | (c - '0');
        bits_collected++;
        if (bits_collected == 6) {
            base64 += base64_chars[accumulator];
            bits_collected = 0;
            accumulator = 0;
        }
    }

    if (bits_collected > 0) {
        accumulator <<= 6 - bits_collected;
        base64 += base64_chars[accumulator];
    }

    while (base64.size() % 4 != 0) {
        base64 += "=";
    }

    return base64;
}

string DES::padTo64Bits(const string& binary) {
    string padded = binary;
    int padding = 64 - (binary.length() % 64);
    if (padding != 64) {
        padded.append(padding, '0');
    }
    return padded;
}

string DES:: extractBinaryStringFromFile(const string& filename) {
    ifstream file(filename);
    string line;
    string binaryString;

    if (file.is_open()) {
        while (getline(file, line)) {
            // Regular expression to match the line containing binary string
            regex binaryRegex("^Binary:\\s*([01]+)$");
            smatch match;

            if (regex_match(line, match, binaryRegex)) {
                // Extract binary string from the matched line
                binaryString = match[1];
                break; // Stop reading file after finding the binary string
            }
        }
        file.close();
    } else {
        cerr << "Unable to open file: " << filename << endl;
    }

    return binaryString;
}

string DES::readFromFile(const string& filename) {
    ifstream file(filename);
    stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void DES::writeToFile(const string& filename, const string& content) {
    ofstream file(filename);
    file << content;
    file.close();
}

void DES::appendToFile(const string& filename, const string& content) {
    ofstream file(filename, ios::app); // Open The File in Append Mode
    file << content;
    file.close();
}

#endif
