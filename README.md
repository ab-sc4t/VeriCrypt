# VeriCrypt

A secure message encryption and signing package using Ed25519 for signing and X25519 for encryption, with support for BIP39 mnemonic key derivation.

## Installation

```bash
npm install vericrypt
```

## Features

- **Single Keypair for Both Operations**: Uses Ed25519 for signing and automatically converts to X25519 for encryption
- **BIP39 Mnemonic Support**: Generate and recover keys from 12-word mnemonic phrases
- **Message signing and verification** using Ed25519
- **Message encryption and decryption** using X25519
- **Forward secrecy** with ephemeral keys for each encryption
- **All keys and messages are base64 encoded** for easy transmission
- **Built on modern noble libraries** for optimal performance and security

## Usage

### Key Generation

#### Random Key Generation

```javascript
const { generateKeyPair } = require('vericrypt');

// Generate key pairs for both signing and encryption
const keys = generateKeyPair();

// Ed25519 keys for signing/verification
console.log('Signing Private Key:', keys.signingPrivateKey);
console.log('Signing Public Key:', keys.signingPublicKey);

// X25519 keys for encryption/decryption (derived from Ed25519)
console.log('Encryption Private Key:', keys.encryptionPrivateKey);
console.log('Encryption Public Key:', keys.encryptionPublicKey);
```

#### Mnemonic-based Key Generation

```javascript
const { generateMnemonicPhrase, generateKeyPairFromMnemonic } = require('vericrypt');

// Generate a new mnemonic phrase
const mnemonic = generateMnemonicPhrase();
console.log('Mnemonic:', mnemonic);
// Output: "cabin extend intact solid replace that aisle ill hospital sister harvest clock"

// Generate keys from mnemonic (uses default path: "m/44'/0'/0'/0'/0'")
const keys = generateKeyPairFromMnemonic(mnemonic);

// Or specify a custom derivation path
const customKeys = generateKeyPairFromMnemonic(mnemonic, "m/44'/0'/0'/0'/1'");
```

### Signing Messages

```javascript
const { sign } = require('vericrypt');

const message = 'Hello, World!';
const signingPrivateKey = keys.signingPrivateKey;

// Sign the message (async operation)
const signedData = await sign(message, signingPrivateKey);
console.log('Message:', signedData.message);
console.log('Signature:', signedData.signature);
```

### Verifying Signatures

```javascript
const { verify } = require('vericrypt');

const signingPublicKey = keys.signingPublicKey;

// Verify the signed message (async operation)
const isValid = await verify(signedData, signingPublicKey);
if (isValid) {
    console.log('Signature is valid');
} else {
    console.log('Signature is invalid');
}
```

### Encrypting Messages

```javascript
const { encrypt } = require('vericrypt');

const message = 'Hello, World!';
const receiverEncryptionPublicKey = recipientKeys.encryptionPublicKey;

// Encrypt the message
const encryptedData = encrypt(message, receiverEncryptionPublicKey);
console.log('Encrypted Message:', encryptedData.encryptedMessage);
console.log('Ephemeral Public Key:', encryptedData.ephemeralPublicKey);
```

### Decrypting Messages

```javascript
const { decrypt } = require('vericrypt');

const receiverEncryptionPrivateKey = recipientKeys.encryptionPrivateKey;

// Decrypt the message
const decryptedMessage = decrypt(encryptedData, receiverEncryptionPrivateKey);
if (decryptedMessage) {
    console.log('Decrypted Message:', decryptedMessage);
} else {
    console.log('Decryption failed');
}
```

### Complete Example: Sign, Encrypt, Decrypt, and Verify

```javascript
const { 
    generateMnemonicPhrase, 
    generateKeyPairFromMnemonic, 
    sign, 
    verify, 
    encrypt, 
    decrypt 
} = require('vericrypt');

async function secureCommunication() {
    // Generate mnemonic and keys for sender and receiver
    const senderMnemonic = generateMnemonicPhrase();
    const receiverMnemonic = generateMnemonicPhrase();
    
    const senderKeys = generateKeyPairFromMnemonic(senderMnemonic);
    const receiverKeys = generateKeyPairFromMnemonic(receiverMnemonic);

    const message = 'Hello, World!';

    // 1. Sign the message with sender's signing key
    const signedData = await sign(message, senderKeys.signingPrivateKey);

    // 2. Encrypt the signed message with receiver's encryption key
    const encryptedData = encrypt(signedData.message, receiverKeys.encryptionPublicKey);

    // ... Send encryptedData and signedData.signature to receiver ...

    // 3. Decrypt the message with receiver's decryption key
    const decryptedMessage = decrypt(encryptedData, receiverKeys.encryptionPrivateKey);

    // 4. Verify the signature with sender's verification key
    const isValid = await verify({
        message: decryptedMessage,
        signature: signedData.signature
    }, senderKeys.signingPublicKey);

    if (isValid && decryptedMessage === message) {
        console.log('Message successfully decrypted and verified!');
    }
}

secureCommunication().catch(console.error);
```

### Alternative: Using Random Keys

```javascript
const { generateKeyPair, sign, verify, encrypt, decrypt } = require('vericrypt');

async function secureCommunicationWithRandomKeys() {
    // Generate random key pairs for sender and receiver
    const senderKeys = generateKeyPair();
    const receiverKeys = generateKeyPair();

    const message = 'Hello, World!';

    // 1. Sign the message with sender's signing key
    const signedData = await sign(message, senderKeys.signingPrivateKey);

    // 2. Encrypt the signed message with receiver's encryption key
    const encryptedData = encrypt(signedData.message, receiverKeys.encryptionPublicKey);

    // 3. Decrypt the message with receiver's decryption key
    const decryptedMessage = decrypt(encryptedData, receiverKeys.encryptionPrivateKey);

    // 4. Verify the signature with sender's verification key
    const isValid = await verify({
        message: decryptedMessage,
        signature: signedData.signature
    }, senderKeys.signingPublicKey);

    if (isValid && decryptedMessage === message) {
        console.log('Message successfully decrypted and verified!');
    }
}

secureCommunicationWithRandomKeys().catch(console.error);
```

## API Reference

### Functions

#### `generateMnemonicPhrase()`
Generates a new 12-word BIP39 mnemonic phrase.
- **Returns:** `string` - 12-word mnemonic phrase

#### `generateKeyPairFromMnemonic(mnemonic, path?)`
Derives keypairs from a BIP39 mnemonic phrase.
- **Parameters:**
  - `mnemonic` (string): BIP39 mnemonic phrase
  - `path` (string, optional): HD derivation path (default: "m/44'/0'/0'/0'/0'")
- **Returns:** Object with base64-encoded keys:
  ```javascript
  {
    signingPrivateKey: string,
    signingPublicKey: string,
    encryptionPrivateKey: string,
    encryptionPublicKey: string
  }
  ```

#### `generateKeyPair()`
Generates a new random keypair for both signing and encryption.
- **Returns:** Object with base64-encoded keys (same structure as above)

#### `sign(message, signingPrivateKey)`
Signs a message using Ed25519.
- **Parameters:**
  - `message` (string): Message to sign
  - `signingPrivateKey` (string): Base64-encoded Ed25519 private key
- **Returns:** `Promise<{message: string, signature: string}>`

#### `verify(signedData, signingPublicKey)`
Verifies a signed message using Ed25519.
- **Parameters:**
  - `signedData` (object): `{message: string, signature: string}`
  - `signingPublicKey` (string): Base64-encoded Ed25519 public key
- **Returns:** `Promise<boolean>`

#### `encrypt(message, receiverEncryptionPublicKey)`
Encrypts a message using X25519.
- **Parameters:**
  - `message` (string): Message to encrypt
  - `receiverEncryptionPublicKey` (string): Base64-encoded X25519 public key
- **Returns:** `{encryptedMessage: string, ephemeralPublicKey: string}`

#### `decrypt(encryptedData, receiverEncryptionPrivateKey)`
Decrypts a message using X25519.
- **Parameters:**
  - `encryptedData` (object): `{encryptedMessage: string, ephemeralPublicKey: string}`
  - `receiverEncryptionPrivateKey` (string): Base64-encoded X25519 private key
- **Returns:** `string | null` - Decrypted message or null if decryption fails

## Security Notes

1. **Keep all private keys secure** and never share them.
2. **Store mnemonics safely** - they can be used to recover all derived keys.
3. **Use different derivation paths** for different purposes to maintain key separation.
4. The package uses:
   - **Ed25519** for signing and verification
   - **X25519** for encryption and decryption (derived from Ed25519 keys)
   - **BIP39** for mnemonic generation
   - **HD key derivation** for deterministic key generation
5. **Each encryption operation** generates a new ephemeral key pair for forward secrecy.
6. **All messages are signed** before encryption to ensure authenticity.
7. **Built on noble libraries** for optimal performance and security.
8. **Async operations** for signing and verification for better performance.

## Dependencies

- `@noble/curves` - Modern cryptographic curves implementation
- `@noble/hashes` - Cryptographic hash functions
- `bip39` - BIP39 mnemonic generation
- `ed25519-hd-key` - HD key derivation for Ed25519

## License

ISC 