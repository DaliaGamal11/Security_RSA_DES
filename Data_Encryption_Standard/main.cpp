#include <iostream>
#include "DES.h"

using namespace std;

int main() {

    DES des;
    // Call DES_Encryption with plaintext and key file paths
    string encryptedText = des.DES_Encryption("plaintext.txt", "key.txt");

    // Decrypt the ciphertext using the same key
    string decryptedText = des.DES_Decryption("ciphertext.txt", "key.txt");

    return 0;
}
