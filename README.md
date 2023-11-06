# CROWNTITANIUM - Asymmetric post-quantum resistant supercipher with 2048 bit security 

a house-made asymmetric supercipher encryption with post-quantum resistance

## Features

- CROWNTITANIUM is a novel in-house made asymmertric supercipher with post-quantum resistancy that I made, so I can encrypt highly dangerous malware and post them here on github so nobody can use them.
- CROWNTITANIUM is a *supercipher* encryption, this means it consists of multiple encryption layers combined. I chose 4 different layers. I will outline them quickly for you.

1. **AES 256 bit**: 
    1. Generates Public and Private Key
2. **CAMELLIA Sub-Supercipher 768 bit**
    1. **Another AES 256 bit Layer**
        1. Generates Public and Private Key
    3. **ChaCha20 256 bit**
        1. Symmetric Key used
    5. **CAMELLIA 256 bit**
        1. Generates Public and Private Key
    7. **Passphrase hashed SHA3-512**
3. **NTRU Prime (Post-Quantum Resistant)**
    1. Generates Public and Private Key using KEM
5. **Kyber-CRYSTAL and dilithium (Post-Quantum Resistant)**
    1. Generates Public and Private Key using KEM

- As you see CROWNTITANIUM uses 11 different keys for a complete encryption or decryption of a file. 

> add support for custom CROWNTITANIUM-over-HTTPS (CoH) and signing support.
