# Anonymous Credit System (ACS)

A Rust implementation of an Anonymous Credit System that enables privacy-preserving digital credits through proof-of-work.

## ⚠️ EXPERIMENTAL DISCLAIMER ⚠️

**THIS CRYPTOGRAPHY IS EXPERIMENTAL AND UNAUDITED. DO NOT USE IN PRODUCTION ENVIRONMENTS.**

This system relies on experimental cryptographic techniques and has not undergone formal security auditing. It is intended solely for research, educational purposes, and experimentation. Using this system in production environments could lead to:

- Loss of privacy
- Security vulnerabilities
- System compromise
- Data loss

## Overview

ACS implements a system where users can:

1. **Issue tokens** by performing computational work (proof-of-work)
2. **Spend tokens** anonymously without revealing their identity
3. **Combine tokens** to consolidate multiple tokens into a single one with their sum value
4. **Manage tokens** through a simple command-line interface

The system maintains privacy through cryptographic techniques that ensure spending a token cannot be linked to its issuance.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/acs.git
cd acs

# Build the project
cargo build --release

# Two binaries will be built:
# - The server: target/release/acs
# - The CLI client: target/release/acs-cli
```

## Usage

### Running the Server

The server component handles token issuance and validation:

```bash
./target/release/acs
```

This starts an HTTPS server with a self-signed certificate on the default port.

### CLI Commands

The project provides a separate CLI binary (`acs-cli`) for managing anonymous credits:

#### Issue Tokens

Generate new tokens by performing proof-of-work:

```bash
./target/release/acs-cli issue --bits 10
```

This will perform computational work to issue a token worth 2^10 (1024) credits.

#### List Available Tokens

View all tokens in your local storage:

```bash
./target/release/acs-cli list
```

#### Show Token Details

Display detailed information about a specific token:

```bash
./target/release/acs-cli show --id <TOKEN_ID>
```

#### Spend Tokens

Use credits from your tokens:

```bash
./target/release/acs-cli spend --id <TOKEN_ID> --amount <AMOUNT>
```

This will spend the specified amount of credits while maintaining anonymity.

#### Combine Tokens

Consolidate multiple tokens into a single token with their combined value:

```bash
./target/release/acs-cli combine --ids <TOKEN_ID_1>,<TOKEN_ID_2>,...
```

This will create a new token with the sum value of all the provided tokens. The original tokens will be spent in the process.

## Technical Details

ACS consists of several components:

- **Server**: An HTTPS server for token issuance, validation, and combining
- **Client Library**: Core functionality for token operations
- **CLI**: Command-line interface for user interactions
- **Storage**: SQLite-based persistent token storage

The system uses a nullifier database to prevent double-spending while maintaining anonymity.

## Security Considerations

- Tokens are stored locally and should be backed up to prevent loss
- The system uses a local database to track spent tokens
- Communication with the server occurs over HTTPS with self-signed certificates
- Proof-of-work parameters can be adjusted to balance security and usability
- Combined tokens provide the same privacy guarantees as newly issued tokens

## Development

Contributions are welcome! Please ensure that you run the test suite before submitting changes:

```bash
cargo test
```
