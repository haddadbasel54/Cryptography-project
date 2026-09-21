# Secure Access to Sound Files 🔐🎵

A cryptographic security project for protecting sound files using a combination of **LEA encryption in CFB mode**, **RSA-based key delivery**, and **Schnorr digital signatures**.

The system provides confidentiality, secure symmetric-key delivery, and integrity/authenticity verification for encrypted sound files.

---

## 📖 Project Overview

Sound files are structured binary files containing headers, metadata, and audio data. Encryption therefore needs to preserve the required structure and ensure that the resulting file can be correctly reconstructed after decryption.

This project implements a secure workflow where:

1. The sound file is encrypted using **LEA in CFB mode**.
2. The LEA symmetric key is encrypted using **RSA** for secure key delivery.
3. A **Schnorr digital signature** is generated over the encrypted data.
4. The encrypted sound file and required cryptographic metadata are stored separately.
5. During decryption, the Schnorr signature is verified before the LEA key is recovered and the sound data is decrypted.

The overall design combines symmetric and asymmetric cryptography to provide a complete secure-access workflow.

---

## 🔐 Cryptographic Components

### LEA

**LEA (Lightweight Encryption Algorithm)** is a symmetric block cipher developed by the **Korea Internet & Security Agency (KISA)**.

The project uses LEA because it is designed to provide efficient encryption with relatively low computational and memory requirements.

LEA supports:

* 128-bit keys
* 192-bit keys
* 256-bit keys
* 128-bit block size
* ARX operations:

  * Addition
  * Rotation
  * XOR

For this project, a **128-bit LEA key** is generated for sound-file encryption.

### CFB Mode

LEA is used in **Cipher Feedback (CFB) mode**.

CFB mode allows the block cipher to operate as a stream-like encryption mechanism. The previous ciphertext block, or the IV for the first block, is encrypted and then XORed with the plaintext.

Simplified flow:

```text
IV / Previous Ciphertext
          │
          ▼
     LEA Encryption
          │
          ▼
       Keystream
          │
          ▼
Plaintext ── XOR ──► Ciphertext
                         │
                         ▼
                  Next Feedback
```

The project uses a randomly generated **128-bit Initialization Vector (IV)** for each encryption operation.

---

## 🔑 RSA Key Delivery

RSA is used to securely deliver the symmetric LEA key to the intended recipient.

The project uses:

* **2048-bit RSA keys**
* Public exponent: **65537**
* A 128-bit LEA encryption key

### Key Delivery Process

```text
              Sender
                 │
                 │ Generate LEA Key
                 ▼
          128-bit LEA Key
                 │
                 │ Encrypt with
                 │ recipient's RSA
                 │ public key
                 ▼
         Encrypted LEA Key
                 │
                 │ Secure transmission
                 ▼
             Recipient
                 │
                 │ RSA private key
                 ▼
          Original LEA Key
```

The LEA key itself is never transmitted directly.

The sender encrypts the LEA key using the recipient's RSA public key. The recipient then uses their private RSA key to recover it.

---

## ✍️ Schnorr Digital Signature

A **Schnorr digital signature** is used to provide integrity and authenticity for the encrypted sound data.

The signature process uses:

* Private key
* Public key
* Random nonce
* Generator
* Commitment
* Challenge

The project generates a signature over the encrypted sound data.

Simplified signing process:

```text
Encrypted Sound Data
         │
         ▼
   Generate Random Nonce
         │
         ▼
     Commitment R
         │
         ▼
 H(R, Public Key, Message)
         │
         ▼
      Challenge
         │
         ▼
   Schnorr Signature
       (r, s)
```

During decryption, the signature is verified using the sender's Schnorr public key.

If verification fails, the decryption process is stopped.

---

## 🏗️ System Architecture

The project combines three cryptographic mechanisms:

```text
                    SOUND FILE
                         │
                         ▼
              ┌────────────────────┐
              │ Generate LEA Key   │
              │   128-bit key      │
              └─────────┬──────────┘
                        │
                        ▼
              ┌────────────────────┐
              │  LEA + CFB Mode    │
              │ Encrypt Sound Data │
              └─────────┬──────────┘
                        │
                        ▼
              ┌────────────────────┐
              │ Schnorr Signature  │
              │ Sign Encrypted Data│
              └─────────┬──────────┘
                        │
                        │
         ┌──────────────┴──────────────┐
         │                             │
         ▼                             ▼
 ┌─────────────────┐           ┌──────────────────┐
 │ Encrypted Sound │           │    Metadata      │
 │     File        │           │                  │
 └─────────────────┘           │ IV               │
                               │ Encrypted LEA Key │
                               │ Schnorr (r,s)     │
                               │ Public Keys       │
                               └──────────────────┘
```

---

# 🔒 Encryption Process

The encryption workflow consists of five main stages.

### 1. LEA Key Generation

A random **16-byte (128-bit)** LEA key is generated.

A random **16-byte IV** is also generated.

The randomness ensures that each encryption operation can use a unique encryption configuration.

---

### 2. LEA Key Protection

The generated LEA key is encrypted using the recipient's **RSA public key**.

This protects the symmetric encryption key while it is being delivered to the recipient.

```text
LEA Key
   │
   ▼
RSA Public Key
   │
   ▼
Encrypted LEA Key
```

Only the holder of the corresponding RSA private key can recover the original LEA key.

---

### 3. Sound Data Encryption

The original sound data is encrypted using **LEA in CFB mode**.

The process works by:

1. Using the IV for the first block.
2. Encrypting the feedback block with LEA.
3. XORing the resulting keystream with the plaintext.
4. Producing the ciphertext.
5. Using the ciphertext as feedback for the next block.

```text
Plaintext Block
       │
       ▼
      XOR ◄──── LEA(IV / Previous Ciphertext)
       │
       ▼
   Ciphertext
       │
       └────────► Feedback
```

---

### 4. Schnorr Signature

After encryption, the encrypted sound data is signed using the Schnorr signature scheme.

The signature consists of two values:

```text
(r, s)
```

The signature allows the recipient to verify that the encrypted data has not been modified.

---

### 5. Output Generation

The encryption process produces two files:

```text
filename.encrypted
filename.meta
```

The `.encrypted` file contains the encrypted sound data.

The `.meta` file contains the information required for decryption, including:

* IV
* RSA-encrypted LEA key
* Schnorr signature values `(r, s)`
* Schnorr public key
* RSA public key

---

# 🔓 Decryption Process

The recipient reverses the encryption process while first verifying the integrity of the encrypted data.

### 1. Read Encrypted Data

The application reads:

* Encrypted sound file
* Metadata file
* IV
* Encrypted LEA key
* Schnorr signature
* Required public/private keys

---

### 2. Verify Schnorr Signature

Before decrypting the sound file, the encrypted data is verified using the Schnorr signature.

```text
Encrypted Data
      │
      ▼
Schnorr Verification
      │
   ┌──┴──┐
   │     │
 Valid  Invalid
   │     │
   ▼     ▼
Continue  STOP
```

If the signature verification fails, the decryption process stops.

This prevents modified or unauthenticated encrypted data from being processed.

---

### 3. Recover the LEA Key

The encrypted LEA key is decrypted using the recipient's RSA private key.

```text
Encrypted LEA Key
        │
        ▼
  RSA Private Key
        │
        ▼
 Original LEA Key
```

The recovered LEA key is then used to decrypt the sound data.

---

### 4. Decrypt Sound Data

The sound data is decrypted using LEA in CFB mode and the stored IV.

For each block:

1. Encrypt the previous ciphertext block.
2. Use the IV for the first block.
3. XOR the result with the encrypted block.
4. Recover the original plaintext.
5. Continue to the next block.

---

### 5. Generate Original Sound File

After decryption, any required padding is removed and the original sound data is written to a new sound file.

The resulting file should match the original sound file before encryption.

---

# 🔄 Complete Workflow

```text
                         ENCRYPTION
                              │
                              ▼
                       Original Sound
                              │
                              ▼
                    Generate LEA Key
                              │
                 ┌────────────┴────────────┐
                 │                         │
                 ▼                         ▼
          LEA + CFB Encryption       RSA Encryption
                 │                         │
                 ▼                         ▼
         Encrypted Sound            Encrypted LEA Key
                 │                         │
                 └────────────┬────────────┘
                              │
                              ▼
                    Schnorr Signature
                              │
                              ▼
                  Encrypted File + Meta
                              │
                              ▼
                           TRANSFER
                              │
                              ▼
                         DECRYPTION
                              │
                              ▼
                    Verify Schnorr Signature
                              │
                       ┌──────┴──────┐
                       │             │
                     Valid         Invalid
                       │             │
                       ▼             ▼
               Recover LEA Key      STOP
                  using RSA
                       │
                       ▼
                 LEA + CFB Decryption
                       │
                       ▼
                 Original Sound File
```

---

# 📂 Output Format

### Encrypted File

```text
example.encrypted
```

Contains the encrypted sound data.

### Metadata File

```text
example.meta
```

Contains the cryptographic information required to process the encrypted file:

```text
IV
Encrypted LEA Key
Schnorr Signature (r, s)
Schnorr Public Key
RSA Public Key
```

---

# 🛠️ Technologies & Concepts

This project demonstrates the practical implementation and integration of:

* Symmetric-key cryptography
* **LEA**
* **Cipher Feedback (CFB) mode**
* Asymmetric cryptography
* **RSA**
* RSA key generation
* RSA-based key delivery
* Digital signatures
* **Schnorr signatures**
* Initialization vectors
* Cryptographic key management
* Secure file encryption
* Sound-file encryption and decryption

---

# 🎯 Security Objectives

The system combines multiple cryptographic mechanisms to address different security requirements:

| Security Requirement             | Mechanism              |
| -------------------------------- | ---------------------- |
| Sound data confidentiality       | LEA                    |
| Secure symmetric-key delivery    | RSA                    |
| Data integrity                   | Schnorr signature      |
| Sender authenticity              | Schnorr signature      |
| Unique encryption initialization | Random IV              |
| Secure key generation            | Random 128-bit LEA key |

The combination of these mechanisms creates a layered security design rather than relying on a single cryptographic algorithm.

---

# 👥 Team

This project was developed by:

* **Basel Haddad**
* **Tamer Talhami**
* **Mohamad Dukhi**
* **Waseem Saleem**

---

# 📚 Project Context

This project was developed as a cryptography/security project demonstrating how different cryptographic primitives can be combined to create a secure file-access system.

The project specifically focuses on protecting sound files while demonstrating:

**Confidentiality → LEA + CFB**

**Key Delivery → RSA**

**Integrity & Authentication → Schnorr Signature**

---

## ⚠️ Disclaimer

This project is intended for **educational and demonstration purposes**.

Cryptographic implementations should be carefully reviewed, tested, and audited before being used to protect sensitive or production data. In particular, custom implementations of cryptographic algorithms and signature schemes should not be assumed to provide production-grade security without appropriate cryptographic review.

---

## 📄 Documentation

The repository includes the project presentation explaining:

* Sound-file structure and encryption requirements
* LEA and its key expansion
* LEA round operations
* CFB encryption and decryption
* RSA key generation and key delivery
* Schnorr signature generation and verification
* Complete encryption workflow
* Complete decryption workflow
