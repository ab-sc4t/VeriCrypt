# VeriCrypt

A secure message encryption and signing package using Ed25519 for signing and X25519 for encryption.

## Installation

```bash
npm install vericrypt
```

## Features

- **Separate Keypairs for Signing and Encryption**: Uses Ed25519 for signing and X25519 for encryption
- **Message signing and verification** using Ed25519
- **Message encryption and decryption** using X25519
- **Forward secrecy** with ephemeral keys for each encryption
- **All keys and messages are base64 encoded** for easy transmission
- **Built on tweetnacl** for proven security and reliability

## Usage

### Key Generation

```javascript
const { generateKeyPair } = require('vericrypt');

// Generate key pairs for both signing and encryption
const keys = generateKeyPair();

// Ed25519 keys for signing/verification
console.log('Signing Private Key:', keys.signingPrivateKey);
console.log('Signing Public Key:', keys.signingPublicKey);

// X25519 keys for encryption/decryption
console.log('Encryption Private Key:', keys.encryptionPrivateKey);
console.log('Encryption Public Key:', keys.encryptionPublicKey);
```

### Signing Messages

```javascript
const { sign } = require('vericrypt');

const message = 'Hello, World!';
const signingPrivateKey = keys.signingPrivateKey;

// Sign the message (synchronous operation)
const signedData = sign(message, signingPrivateKey);
console.log('Message:', signedData.message);
console.log('Signature:', signedData.signature);
```

### Verifying Signatures

```javascript
const { verify } = require('vericrypt');

const signingPublicKey = keys.signingPublicKey;

// Verify the signed message (synchronous operation)
const isValid = verify(signedData, signingPublicKey);
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
console.log('Nonce:', encryptedData.nonce);
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
const { generateKeyPair, sign, verify, encrypt, decrypt } = require('vericrypt');

// Generate random key pairs for sender and receiver
const senderKeys = generateKeyPair();
const receiverKeys = generateKeyPair();

const message = 'Hello, World!';

// 1. Sign the message with sender's signing key
const signedData = sign(message, senderKeys.signingPrivateKey);

// 2. Encrypt the signed message with receiver's encryption key
const encryptedData = encrypt(signedData.message, receiverKeys.encryptionPublicKey);

// 3. Decrypt the message with receiver's decryption key
const decryptedMessage = decrypt(encryptedData, receiverKeys.encryptionPrivateKey);

// 4. Verify the signature with sender's verification key
const isValid = verify({
    message: decryptedMessage,
    signature: signedData.signature
}, senderKeys.signingPublicKey);

if (isValid && decryptedMessage === message) {
    console.log('Message successfully decrypted and verified!');
}
```

## API Reference

### Functions

#### `generateKeyPair()`
Generates a new random keypair for both signing and encryption.
- **Returns:** Object with base64-encoded keys:
  ```javascript
  {
    signingPrivateKey: string,
    signingPublicKey: string,
    encryptionPrivateKey: string,
    encryptionPublicKey: string
  }
  ```

#### `sign(message, signingPrivateKey)`
Signs a message using Ed25519.
- **Parameters:**
  - `message` (string): Message to sign
  - `signingPrivateKey` (string): Base64-encoded Ed25519 private key
- **Returns:** `{message: string, signature: string}`

#### `verify(signedData, signingPublicKey)`
Verifies a signed message using Ed25519.
- **Parameters:**
  - `signedData` (object): `{message: string, signature: string}`
  - `signingPublicKey` (string): Base64-encoded Ed25519 public key
- **Returns:** `boolean`

#### `encrypt(message, receiverEncryptionPublicKey)`
Encrypts a message using X25519.
- **Parameters:**
  - `message` (string): Message to encrypt
  - `receiverEncryptionPublicKey` (string): Base64-encoded X25519 public key
- **Returns:** `{encryptedMessage: string, nonce: string, ephemeralPublicKey: string}`

#### `decrypt(encryptedData, receiverEncryptionPrivateKey)`
Decrypts a message using X25519.
- **Parameters:**
  - `encryptedData` (object): `{encryptedMessage: string, nonce: string, ephemeralPublicKey: string}`
  - `receiverEncryptionPrivateKey` (string): Base64-encoded X25519 private key
- **Returns:** `string | null` - Decrypted message or null if decryption fails

## Security Notes

1. **Keep all private keys secure** and never share them.
2. The package uses:
   - **Ed25519** for signing and verification
   - **X25519** for encryption and decryption
   - **tweetnacl** for cryptographic operations
3. **Each encryption operation** generates a new ephemeral key pair for forward secrecy.
4. **All messages are signed** before encryption to ensure authenticity.
5. **Built on tweetnacl** for proven security and reliability.
6. **Synchronous operations** for better performance and simplicity.

## Dependencies

- `tweetnacl` - Proven cryptographic library for Ed25519 and X25519
- `tweetnacl-util` - Utility functions for tweetnacl

## License

ISC 