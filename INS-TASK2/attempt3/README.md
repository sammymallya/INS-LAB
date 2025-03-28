# Secure Key Management System

## Overview
This is a comprehensive key management system that implements various cryptographic operations including key generation, storage, exchange, revocation, and authentication. The system supports both symmetric (AES) and asymmetric (RSA) encryption.

## Project Structure
```
attempt3/
├── aes_keygen.py          # AES key generation and management
├── rsagen.py              # RSA key pair generation
├── certificate_manager.py # X.509 certificate management
├── krl_manager.py         # Key Revocation List management
├── authentication.py      # Message signing and verification
├── key_ex.py             # Diffie-Hellman key exchange
├── enc_dec.py            # Encryption and decryption utilities
├── main.py               # Main application interface
└── krl.json              # Key Revocation List storage
```

## Components Overview

### 1. Key Generation
- **AES Key Generation** (`aes_keygen.py`): Generates secure AES keys for symmetric encryption
- **RSA Key Generation** (`rsagen.py`): Creates RSA key pairs for asymmetric encryption

### 2. Certificate Management
- **Certificate Manager** (`certificate_manager.py`): Handles X.509 certificate generation and validation
- Manages trusted keys and certificate storage

### 3. Key Revocation
- **KRL Manager** (`krl_manager.py`): Manages the Key Revocation List
- Handles key revocation and status checking
- Stores revoked key information in `krl.json`

### 4. Authentication
- **Authentication** (`authentication.py`): Implements message signing and verification
- Uses RSA private/public key pairs for digital signatures

### 5. Key Exchange
- **Key Exchange** (`key_ex.py`): Implements Diffie-Hellman key exchange
- Enables secure key sharing between parties

### 6. Encryption/Decryption
- **Enc/Dec** (`enc_dec.py`): Provides encryption and decryption utilities
- Supports both AES and RSA operations

## Installation

### Prerequisites
- Python 3.8 or higher
- cryptography library

### Setup
1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install cryptography
```

## Usage

### Running the System
```bash
python main.py
```

The main interface provides options for:
1. Generating AES keys
2. Generating RSA key pairs
3. Managing X.509 certificates
4. Revoking keys
5. Checking key revocation status
6. Signing and verifying messages
7. Performing key exchange

## Security Considerations

### Key Storage
- Private keys are stored securely with proper permissions
- Keys are never stored in plain text
- Access to private keys is restricted

### Key Sizes
- RSA keys: 2048 bits minimum
- AES keys: 256 bits

### Best Practices
- Regular key rotation
- Proper key backup procedures
- Secure key storage
- Access control implementation
- Audit logging

## Implementation Details

### Key Generation
- AES keys are generated using cryptographically secure random number generation
- RSA keys are generated with proper key size and public exponent
- Keys are stored in appropriate formats (PEM for RSA, binary for AES)

### Certificate Management
- X.509 certificates are generated with proper validity periods
- Certificate validation includes signature verification
- Certificate revocation is supported

### Key Revocation
- Revoked keys are stored in a JSON-based KRL
- Key status can be checked before use
- Revocation can be temporary or permanent

### Authentication
- Digital signatures use RSA with SHA-256
- Message verification includes proper padding
- Signature verification is performed before accepting messages

### Key Exchange
- Diffie-Hellman key exchange with proper group parameters
- Shared secret computation with key derivation
- Secure key exchange protocol implementation

## Error Handling
- All cryptographic operations include proper error handling
- Invalid keys are detected and rejected
- Failed operations provide meaningful error messages
- System maintains consistency even after errors

## Logging and Monitoring
- Cryptographic operations are logged
- Key usage is tracked
- Security events are recorded
- System state is monitored

## Contributing
Feel free to contribute to this project by:
1. Reporting bugs
2. Suggesting improvements
3. Adding new features
4. Improving documentation

## License
This project is licensed under the MIT License - see the LICENSE file for details. 