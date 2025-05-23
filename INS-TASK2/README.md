# Secure Key Management System

## Overview
This is a comprehensive key management system that implements various cryptographic operations including key generation, storage, exchange, revocation, and authentication. The system supports both symmetric (AES) and asymmetric (RSA) encryption.

## Features

- Certificate Authority (CA) for user authentication
- User-specific key pairs and certificates
- Message signing and verification with JSON formatting
- REST API for integration with Postman
- Secure key storage and management
- Key revocation support

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

1. Clone the repository
2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
3. Install dependencies:
```bash
   pip install -r requirements.txt
   ```

## API Usage with Postman

The system provides a REST API that can be tested using Postman. The base URL is `http://localhost:5000/api`.

### 1. Register a User

**Endpoint:** `POST /api/register`

**Request Body:**
```json
{
    "user_id": "your_user_id"
}
```

**Response:**
```json
{
    "status": "success",
    "user_id": "your_user_id",
    "private_key": "-----BEGIN PRIVATE KEY-----\n..."
}
```

### 2. Sign a Message

**Endpoint:** `POST /api/sign`

**Request Body:**
```json
{
    "user_id": "your_user_id",
    "message": "Your message to sign",
    "private_key": "-----BEGIN PRIVATE KEY-----\n..."
}
```

**Response:**
```json
{
    "version": "1.0",
    "timestamp": "2024-01-01T12:00:00Z",
    "user_id": "your_user_id",
    "message": "Your message to sign",
    "signature": "hex_signature",
    "certificate": {
        "serial_number": "123456789",
        "issuer": "CN=your_user_id,O=User Certificate",
        "valid_from": "2024-01-01T12:00:00Z",
        "valid_to": "2025-01-01T12:00:00Z"
    }
}
```

### 3. Verify a Message

**Endpoint:** `POST /api/verify`

**Request Body:**
```json
{
    "signed_message": {
        "version": "1.0",
        "timestamp": "2024-01-01T12:00:00Z",
        "user_id": "your_user_id",
        "message": "Your message to sign",
        "signature": "hex_signature",
        "certificate": {
            "serial_number": "123456789",
            "issuer": "CN=your_user_id,O=User Certificate",
            "valid_from": "2024-01-01T12:00:00Z",
            "valid_to": "2025-01-01T12:00:00Z"
        }
    }
}
```

**Response:**
```json
{
    "valid": true,
    "message_data": {
        "user_id": "your_user_id",
        "message": "Your message to sign",
        "timestamp": "2024-01-01T12:00:00Z",
        "certificate_info": {
            "serial_number": "123456789",
            "issuer": "CN=your_user_id,O=User Certificate",
            "valid_from": "2024-01-01T12:00:00Z",
            "valid_to": "2025-01-01T12:00:00Z"
        }
    }
}
```

If the message is invalid or tampered with:
```json
{
    "valid": false,
    "error": "Invalid signature"
}
```

### 4. Revoke a Certificate

**Endpoint:** `POST /api/revoke`

**Request Body:**
```json
{
    "user_id": "your_user_id"
}
```

**Response:**
```json
{
    "status": "success",
    "message": "Certificate revoked"
}
```

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