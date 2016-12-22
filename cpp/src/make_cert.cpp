#include <iostream>
#include <cryptopp/rsa.h>
#include <cryptopp/files.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>

using namespace std;
using namespace CryptoPP;

int main(int argc, char** argv) {

    // Create Keys
    // RSA::PrivateKey privateKey;
    // privateKey.GenerateRandomWithKeySize(rng, 3072);
    // RSA::PublicKey publicKey(privateKey);
    AutoSeededRandomPool rng;

    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 3072);

    RSA::PrivateKey privateKey(params);
    RSA::PublicKey publicKey(params);

    string plain="RSA Encryption", cipher, recovered;

    ////////////////////////////////////////////////
    // Encryption
    RSAES_OAEP_SHA_Encryptor e(publicKey);

    StringSource ss1(plain, true,
        new PK_EncryptorFilter(rng, e,
            new StringSink(cipher)
    ) // PK_EncryptorFilter
    ); // StringSource

    ////////////////////////////////////////////////
    // Decryption
    RSAES_OAEP_SHA_Decryptor d(privateKey);

    StringSource ss2(cipher, true,
        new PK_DecryptorFilter(rng, d,
            new StringSink(recovered)
    ) // PK_DecryptorFilter
    ); // StringSource

    cout << "Recovered plain text" << endl;

    cout << "Hello World." << endl;
}