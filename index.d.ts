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
     * Generates a new key pair for both signing and encryption
     * @returns Object containing both signing and encryption key pairs
     */
    export function generateKeyPair(): KeyPair;

    /**
     * Signs a message using the sender's private key
     * @param message - Message to sign
     * @param signingPrivateKey - Sender's Ed25519 private key (base64 encoded)
     * @returns Object containing the message and its signature
     */
    export function sign(message: string, signingPrivateKey: string): SignedData;

    /**
     * Verifies a signed message using the sender's public key
     * @param signedData - Object containing message and signature
     * @param signingPublicKey - Sender's Ed25519 public key (base64 encoded)
     * @returns True if verification succeeds, false otherwise
     */
    export function verify(signedData: SignedData, signingPublicKey: string): boolean;

    /**
     * Encrypts a message using the receiver's public key
     * @param message - Message to encrypt
     * @param receiverEncryptionPublicKey - Receiver's X25519 public key (base64 encoded)
     * @returns Object containing encrypted message, nonce, and ephemeral public key
     */
    export function encrypt(message: string, receiverEncryptionPublicKey: string): EncryptedData;

    /**
     * Decrypts a message using the receiver's private key
     * @param encryptedData - Object containing encrypted message, nonce, and ephemeral public key
     * @param receiverEncryptionPrivateKey - Receiver's X25519 private key (base64 encoded)
     * @returns Decrypted message if successful, null otherwise
     */
    export function decrypt(encryptedData: EncryptedData, receiverEncryptionPrivateKey: string): string | null;
} 