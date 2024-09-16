#ifndef RSA_H_INCLUDED
#define RSA_H_INCLUDED

#include <iostream>

using namespace std;

class RSA {
    private:
        int p;
        int q;
        int n;
        int e;
        int d;
        int m;
        int c;

        int RSA_Encryption(int);
        int RSA_Decryption(int);
        bool isPrime(int );
        int gcd(int, int);
        int findE(int);
        int findD(int, int);
        void generateKeys(); // Generate Public and Private Keys
        int modularExponentiation(int, unsigned int, int); // Computes The Modular Exponentiation (pow(base, exponent) % modulusValue)

    public:
        RSA();
};

RSA::RSA() {
    generateKeys();

    do {
        cout << endl << "Enter Message to Encrypt (Message Must be Less Than n = " << n << "): ";
        cin >> m;
    } while (m >= n);

    c = RSA_Encryption(m);
    cout << endl << "Encrypted Message: " << c << endl;

    int decrypted = RSA_Decryption(c);
    cout << "Decrypted Message: " << decrypted << endl;
}

int RSA::RSA_Encryption(int m) {
    return modularExponentiation(m, e, n);
}

int RSA::RSA_Decryption(int c) {
    return modularExponentiation(c, d, n);
}

bool RSA::isPrime(int n) {
    if (n <= 1) return false;
    if (n <= 3) return true;

    if (n % 2 == 0 || n % 3 == 0) return false;

    for (int i = 5; i * i <= n; i += 6)
        if (n % i == 0 || n % (i + 2) == 0)
            return false;

        return true;
}

int RSA::gcd(int a, int b) {
    if (b == 0) return a;
    return gcd(b, a % b);
}

int RSA::findE(int phi) {
    int e = 2;
    while (e < phi) {
        if (gcd(e, phi) == 1)
            break;
        e++;
    }
    return e;
}

int RSA::findD(int e, int phi) {
    int d = 0;
    int k = 1;
    while ((1 + (k * phi  )) % e != 0) {
        k++;
    }
    d = (1 + (k * phi)) / e;
    return d;
}

void RSA::generateKeys() {
    do {
        cout << "Enter The First Prime Number  (p): ";
        cin >> p;
    } while (!isPrime(p));

    do {
        cout << "Enter The Second Prime Number (q): ";
        cin >> q;
    } while (!isPrime(q));
    n = p * q;

    int phi = (p - 1) * (q - 1);

    e = findE(phi);
    cout << "e: " << e << endl;
    d = findD(e, phi);
    cout << "d: " << d << endl;
}

int RSA::modularExponentiation(int base, unsigned int exponent, int modulusValue) {
    int result = 1;
    base = base % modulusValue;

    while (exponent > 0) {
        if (exponent & 1){
            result = (result * base) % modulusValue;
        }
        exponent = exponent / 2;
        base = (base * base) % modulusValue;
    }

    return result;
}
#endif
