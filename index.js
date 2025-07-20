const nacl = require('tweetnacl');
const naclUtil = require('tweetnacl-util');

/**
 * Generates a new Ed25519 key pair
 * @returns {Object} Object containing base64 encoded private and public keys
 */
function generateKeyPair() {
    // Generate a key pair for encryption (X25519)
    const encryptionKeyPair = nacl.box.keyPair();
    // Generate a key pair for signing (Ed25519)
    const signingKeyPair = nacl.sign.keyPair();
    
    return {
        // For encryption
        encryptionPrivateKey: naclUtil.encodeBase64(encryptionKeyPair.secretKey),
        encryptionPublicKey: naclUtil.encodeBase64(encryptionKeyPair.publicKey),
        // For signing
        signingPrivateKey: naclUtil.encodeBase64(signingKeyPair.secretKey),
        signingPublicKey: naclUtil.encodeBase64(signingKeyPair.publicKey)
    };
}

/**
 * Signs a message using the sender's private key
 * @param {string} message - Message to sign
 * @param {string} signingPrivateKey - Sender's Ed25519 private key (base64 encoded)
 * @returns {Object} Object containing the message and its signature
 */
function sign(message, signingPrivateKey) {
    const privateKeyBytes = naclUtil.decodeBase64(signingPrivateKey);
    const messageBytes = naclUtil.decodeUTF8(message);
    
    const signature = nacl.sign.detached(messageBytes, privateKeyBytes);
    
    return {
        message: message,
        signature: naclUtil.encodeBase64(signature)
    };
}

/**
 * Verifies a signed message using the sender's public key
 * @param {Object} signedData - Object containing message and signature
 * @param {string} signingPublicKey - Sender's Ed25519 public key (base64 encoded)
 * @returns {boolean} True if verification succeeds, false otherwise
 */
function verify(signedData, signingPublicKey) {
    const publicKeyBytes = naclUtil.decodeBase64(signingPublicKey);
    const messageBytes = naclUtil.decodeUTF8(signedData.message);
    const signature = naclUtil.decodeBase64(signedData.signature);
    
    return nacl.sign.detached.verify(
        messageBytes,
        signature,
        publicKeyBytes
    );
}

/**
 * Encrypts a message using the receiver's public key
 * @param {string} message - Message to encrypt
 * @param {string} receiverEncryptionPublicKey - Receiver's X25519 public key (base64 encoded)
 * @returns {Object} Object containing encrypted message and nonce
 */
function encrypt(message, receiverEncryptionPublicKey) {
    const receiverPublicKeyBytes = naclUtil.decodeBase64(receiverEncryptionPublicKey);
    const messageBytes = naclUtil.decodeUTF8(message);
    
    const ephemeralKeyPair = nacl.box.keyPair();
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    
    const encryptedMessage = nacl.box(
        messageBytes,
        nonce,
        receiverPublicKeyBytes,
        ephemeralKeyPair.secretKey
    );
    
    return {
        encryptedMessage: naclUtil.encodeBase64(encryptedMessage),
        nonce: naclUtil.encodeBase64(nonce),
        ephemeralPublicKey: naclUtil.encodeBase64(ephemeralKeyPair.publicKey)
    };
}

/**
 * Decrypts a message using the receiver's private key
 * @param {Object} encryptedData - Object containing encrypted message, nonce, and ephemeral public key
 * @param {string} receiverEncryptionPrivateKey - Receiver's X25519 private key (base64 encoded)
 * @returns {string} Decrypted message if successful, null otherwise
 */
function decrypt(encryptedData, receiverEncryptionPrivateKey) {
    const receiverPrivateKeyBytes = naclUtil.decodeBase64(receiverEncryptionPrivateKey);
    const encryptedMessageBytes = naclUtil.decodeBase64(encryptedData.encryptedMessage);
    const nonceBytes = naclUtil.decodeBase64(encryptedData.nonce);
    const ephemeralPublicKeyBytes = naclUtil.decodeBase64(encryptedData.ephemeralPublicKey);
    
    const decryptedMessage = nacl.box.open(
        encryptedMessageBytes,
        nonceBytes,
        ephemeralPublicKeyBytes,
        receiverPrivateKeyBytes
    );
    
    if (!decryptedMessage) {
        return null;
    }
    
    return naclUtil.encodeUTF8(decryptedMessage);
}

module.exports = {
    generateKeyPair,
    sign,
    verify,
    encrypt,
    decrypt
}; 