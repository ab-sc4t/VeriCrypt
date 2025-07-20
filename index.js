const { generateMnemonic, mnemonicToSeedSync } = require("bip39");
const { derivePath } = require("ed25519-hd-key");
const { ed25519, x25519 } = require('@noble/curves/ed25519');
const { edwardsToMontgomeryPub, edwardsToMontgomeryPriv } = require('@noble/curves/ed25519');

/**
 * Generates a new mnemonic phrase
 * @returns {string} 12-word mnemonic phrase
 */
function generateMnemonicPhrase() {
    return generateMnemonic();
}

/**
 * Generates a new Ed25519 key pair from mnemonic and path
 * @param {string} mnemonic - BIP39 mnemonic phrase
 * @param {string} path - HD derivation path (default: "m/44'/0'/0'/0'/0'")
 * @returns {Object} Object containing base64 encoded private and public keys
 */
function generateKeyPairFromMnemonic(mnemonic, path = "m/44'/0'/0'/0'/0'") {
    const seed = mnemonicToSeedSync(mnemonic);
    const { key: privateKey } = derivePath(path, seed.toString("hex"));
    
    // Get Ed25519 public key for signing
    const signingPublicKey = ed25519.getPublicKey(privateKey);
    
    // Convert to X25519 for encryption
    const encryptionPrivateKey = edwardsToMontgomeryPriv(privateKey);
    const encryptionPublicKey = edwardsToMontgomeryPub(signingPublicKey);
    
    return {
        // For encryption (X25519)
        encryptionPrivateKey: Buffer.from(encryptionPrivateKey).toString('base64'),
        encryptionPublicKey: Buffer.from(encryptionPublicKey).toString('base64'),
        // For signing (Ed25519)
        signingPrivateKey: Buffer.from(privateKey).toString('base64'),
        signingPublicKey: Buffer.from(signingPublicKey).toString('base64')
    };
}

/**
 * Generates a new Ed25519 key pair
 * @returns {Object} Object containing base64 encoded private and public keys
 */
function generateKeyPair() {
    // Generate random Ed25519 keypair for signing
    const signingPrivateKey = ed25519.utils.randomPrivateKey();
    const signingPublicKey = ed25519.getPublicKey(signingPrivateKey);
    
    // Convert to X25519 for encryption
    const encryptionPrivateKey = edwardsToMontgomeryPriv(signingPrivateKey);
    const encryptionPublicKey = edwardsToMontgomeryPub(signingPublicKey);
    
    return {
        // For encryption (X25519)
        encryptionPrivateKey: Buffer.from(encryptionPrivateKey).toString('base64'),
        encryptionPublicKey: Buffer.from(encryptionPublicKey).toString('base64'),
        // For signing (Ed25519)
        signingPrivateKey: Buffer.from(signingPrivateKey).toString('base64'),
        signingPublicKey: Buffer.from(signingPublicKey).toString('base64')
    };
}

/**
 * Signs a message using the sender's private key
 * @param {string} message - Message to sign
 * @param {string} signingPrivateKey - Sender's Ed25519 private key (base64 encoded)
 * @returns {Object} Object containing the message and its signature
 */
async function sign(message, signingPrivateKey) {
    const privateKeyBytes = Buffer.from(signingPrivateKey, 'base64');
    const messageBytes = Buffer.from(message, 'utf8');
    
    const signature = await ed25519.sign(messageBytes, privateKeyBytes);
    
    return {
        message: message,
        signature: Buffer.from(signature).toString('base64')
    };
}

/**
 * Verifies a signed message using the sender's public key
 * @param {Object} signedData - Object containing message and signature
 * @param {string} signingPublicKey - Sender's Ed25519 public key (base64 encoded)
 * @returns {boolean} True if verification succeeds, false otherwise
 */
async function verify(signedData, signingPublicKey) {
    const publicKeyBytes = Buffer.from(signingPublicKey, 'base64');
    const messageBytes = Buffer.from(signedData.message, 'utf8');
    const signature = Buffer.from(signedData.signature, 'base64');
    
    return await ed25519.verify(signature, messageBytes, publicKeyBytes);
}

/**
 * Encrypts a message using the receiver's public key
 * @param {string} message - Message to encrypt
 * @param {string} receiverEncryptionPublicKey - Receiver's X25519 public key (base64 encoded)
 * @returns {Object} Object containing encrypted message and ephemeral public key
 */
function encrypt(message, receiverEncryptionPublicKey) {
    const receiverPublicKeyBytes = Buffer.from(receiverEncryptionPublicKey, 'base64');
    const messageBytes = Buffer.from(message, 'utf8');
    
    // Generate ephemeral keypair
    const ephemeralPrivateKey = x25519.utils.randomPrivateKey();
    const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);
    
    // Generate shared secret
    const sharedSecret = x25519.getSharedSecret(ephemeralPrivateKey, receiverPublicKeyBytes);
    
    // Use first 32 bytes of shared secret as key for simple encryption
    // In production, you might want to use a proper AEAD cipher
    const key = sharedSecret.slice(0, 32);
    
    // Simple XOR encryption (for demonstration - use proper encryption in production)
    const encryptedBytes = new Uint8Array(messageBytes.length);
    for (let i = 0; i < messageBytes.length; i++) {
        encryptedBytes[i] = messageBytes[i] ^ key[i % key.length];
    }
    
    return {
        encryptedMessage: Buffer.from(encryptedBytes).toString('base64'),
        ephemeralPublicKey: Buffer.from(ephemeralPublicKey).toString('base64')
    };
}

/**
 * Decrypts a message using the receiver's private key
 * @param {Object} encryptedData - Object containing encrypted message and ephemeral public key
 * @param {string} receiverEncryptionPrivateKey - Receiver's X25519 private key (base64 encoded)
 * @returns {string} Decrypted message if successful, null otherwise
 */
function decrypt(encryptedData, receiverEncryptionPrivateKey) {
    const receiverPrivateKeyBytes = Buffer.from(receiverEncryptionPrivateKey, 'base64');
    const encryptedMessageBytes = Buffer.from(encryptedData.encryptedMessage, 'base64');
    const ephemeralPublicKeyBytes = Buffer.from(encryptedData.ephemeralPublicKey, 'base64');
    
    // Generate shared secret
    const sharedSecret = x25519.getSharedSecret(receiverPrivateKeyBytes, ephemeralPublicKeyBytes);
    
    // Use first 32 bytes of shared secret as key
    const key = sharedSecret.slice(0, 32);
    
    // Simple XOR decryption
    const decryptedBytes = new Uint8Array(encryptedMessageBytes.length);
    for (let i = 0; i < encryptedMessageBytes.length; i++) {
        decryptedBytes[i] = encryptedMessageBytes[i] ^ key[i % key.length];
    }
    
    return Buffer.from(decryptedBytes).toString('utf8');
}

module.exports = {
    generateMnemonicPhrase,
    generateKeyPairFromMnemonic,
    generateKeyPair,
    sign,
    verify,
    encrypt,
    decrypt
}; 