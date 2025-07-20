declare module 'vericrypt' {
    /**
     * Key pair containing both signing and encryption keys
     */
    interface KeyPair {
        signingPrivateKey: string;
        signingPublicKey: string;
        encryptionPrivateKey: string;
        encryptionPublicKey: string;
    }

    /**
     * Signed message data
     */
    interface SignedData {
        message: string;
        signature: string;
    }

    /**
     * Encrypted message data
     */
    interface EncryptedData {
        encryptedMessage: string;
        nonce: string;
        ephemeralPublicKey: string;
    }

    /**
     * Generates a new Ed25519 key pair
     * @returns {Object} Object containing base64 encoded private and public keys
     */
    export function generateKeyPair(): {
        encryptionPrivateKey: string;
        encryptionPublicKey: string;
        signingPrivateKey: string;
        signingPublicKey: string;
    };

    /**
     * Signs a message using the sender's private key
     * @param {string} message - Message to sign
     * @param {string} signingPrivateKey - Sender's Ed25519 private key (base64 encoded)
     * @returns {Object} Object containing the message and its signature
     */
    export function sign(message: string, signingPrivateKey: string): {
        message: string;
        signature: string;
    };

    /**
     * Verifies a signed message using the sender's public key
     * @param {Object} signedData - Object containing message and signature
     * @param {string} signingPublicKey - Sender's Ed25519 public key (base64 encoded)
     * @returns {boolean} True if verification succeeds, false otherwise
     */
    export function verify(signedData: {
        message: string;
        signature: string;
    }, signingPublicKey: string): boolean;

    /**
     * Encrypts a message using the receiver's public key
     * @param {string} message - Message to encrypt
     * @param {string} receiverEncryptionPublicKey - Receiver's X25519 public key (base64 encoded)
     * @returns {Object} Object containing encrypted message, nonce, and ephemeral public key
     */
    export function encrypt(message: string, receiverEncryptionPublicKey: string): {
        encryptedMessage: string;
        nonce: string;
        ephemeralPublicKey: string;
    };

    /**
     * Decrypts a message using the receiver's private key
     * @param {Object} encryptedData - Object containing encrypted message, nonce, and ephemeral public key
     * @param {string} receiverEncryptionPrivateKey - Receiver's X25519 private key (base64 encoded)
     * @returns {string} Decrypted message if successful, null otherwise
     */
    export function decrypt(encryptedData: {
        encryptedMessage: string;
        nonce: string;
        ephemeralPublicKey: string;
    }, receiverEncryptionPrivateKey: string): string | null;
} 