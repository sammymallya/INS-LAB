# Key Management System

A comprehensive key management system that handles both symmetric and asymmetric encryption.

## Features

- Symmetric key generation and management
- Asymmetric key generation and management (PKI)
- Secure key storage
- Key exchange using Diffie-Hellman
- Key revocation system
- Key rotation policies

## Project Structure

```
INS_TASK/
├── sym_key_management.py    # Symmetric key operations
├── asym_key_management.py   # Asymmetric key operations
├── key_storage.py          # Secure key storage
├── key_exchange.py         # Diffie-Hellman key exchange
├── utils.py               # Utility functions
├── tests/                 # Test files
└── requirements.txt       # Project dependencies
```

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

See individual module documentation for usage examples.

## Security Considerations

- All keys are stored in encrypted form
- Keys are rotated regularly
- Proper key revocation is implemented
- Protection against common attacks 