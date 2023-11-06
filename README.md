# CROWNTITANIUM - Asymmetric post-quantum resistant supercipher with 2048 bit security 

an in-house made asymmetric supercipher encryption with post-quantum resistance. intended to be used for file encryption. possibly the most powerful open-source encryption to-date. 

## Features

- CROWNTITANIUM is a novel in-house made asymmertric supercipher with post-quantum resistancy that I made, so I can encrypt highly dangerous malware and post them here on github so nobody can use them.
- CROWNTITANIUM is a *supercipher* encryption, this means it consists of multiple encryption layers combined. I chose 4 different layers. I will outline them quickly for you.

> Let's take a plaintext file for our example scenario.

1. **AES 256 bit**: Plaintext file will be encrypted using AES 256 bit algorithm.
    1. Generates Public and Private Key used for encrypting and decrypting the file
2. **CAMELLIA Sub-Supercipher 768 bit**: On top of that first encryption layer (AES 256), the file will be encrypted again using a sub-supercipher.
    1. **Another AES 256 bit Layer**: First the file will be encrypted again using AES 256 bit algorithm. this extends the composable security of this sub-cipher. 
        1. Generates Public and Private Key for encrypting and decrypting the file
    3. **ChaCha20 256 bit**: The encrypted AES 256 bit file will go through another layer of encryption. this time with a ChaCha20 256 bit algorithm.
        1. Symmetric Key used
    5. **CAMELLIA 256 bit**:  The final encryption layer of this sub-supercipher uses a strong asymmetric CAMELLIA 256 bit layer.
        1. Generates Public and Private Key 
    7. **Passphrase hashed SHA3-512** The resulting keys of the sub-supercipher will be hashed using SHA3-512
3. **NTRU Prime (Post-Quantum Resistant)**: After completing the CAMELLIA sub-supercipher, the file will be encrypted using a quantum-resistant algorithm called NTRU prime. NTRU Prime is known to be very efficient.
    1. Generates Public and Private Key using KEM
5. **Kyber-CRYSTAL and dilithium (Post-Quantum Resistant)**: The last encryption layer is a Kyber-CRYSTAL and dilithium algorithm which is known to be extremely performant.
    1. Generates Public and Private Key using KEM

- As you see CROWNTITANIUM uses 11 different keys for a complete encryption or decryption of a file. 

> add support for custom CROWNTITANIUM-over-HTTPS (CoH) and signing support.
