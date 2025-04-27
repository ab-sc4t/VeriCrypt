const { generateKeyPair, sign, verify, encrypt, decrypt } = require('./index.js');

// Test message
const message = 'Hello, this is a test message!';

console.log('=== Starting VeriCrypt Test ===\n');

// Step 1: Generate key pairs for sender and receiver
console.log('1. Generating key pairs...');
const senderKeys = generateKeyPair();
const receiverKeys = generateKeyPair();
console.log('   Sender Signing Public Key:', senderKeys.signingPublicKey.substring(0, 20) + '...');
console.log('   Sender Encryption Public Key:', senderKeys.encryptionPublicKey.substring(0, 20) + '...');
console.log('   Receiver Encryption Public Key:', receiverKeys.encryptionPublicKey.substring(0, 20) + '...\n');

// Step 2: Sign the message
console.log('2. Signing the message...');
const signedData = sign(message, senderKeys.signingPrivateKey);
console.log('   Original Message:', signedData.message);
console.log('   Signature:', signedData.signature.substring(0, 20) + '...\n');

// Step 3: Verify the signature
console.log('3. Verifying the signature...');
const isValid = verify(signedData, senderKeys.signingPublicKey);
console.log('   Signature is valid:', isValid);
if (!isValid) {
    console.error('   ❌ Signature verification failed!');
    process.exit(1);
}
console.log('   ✅ Signature verification successful!\n');

// Step 4: Encrypt the message
console.log('4. Encrypting the message...');
const encryptedData = encrypt(signedData.message, receiverKeys.encryptionPublicKey);
console.log('   Encrypted Message:', encryptedData.encryptedMessage.substring(0, 20) + '...');
console.log('   Nonce:', encryptedData.nonce.substring(0, 20) + '...');
console.log('   Ephemeral Public Key:', encryptedData.ephemeralPublicKey.substring(0, 20) + '...\n');

// Step 5: Decrypt the message
console.log('5. Decrypting the message...');
const decryptedMessage = decrypt(encryptedData, receiverKeys.encryptionPrivateKey);
if (!decryptedMessage) {
    console.error('   ❌ Decryption failed!');
    process.exit(1);
}
console.log('   Decrypted Message:', decryptedMessage);
console.log('   ✅ Decryption successful!\n');

// Step 6: Verify the decrypted message matches the original
console.log('6. Verifying the decrypted message...');
if (decryptedMessage === message) {
    console.log('   ✅ Decrypted message matches the original message!');
} else {
    console.error('   ❌ Decrypted message does not match the original message!');
    process.exit(1);
}

console.log('\n=== All tests completed successfully! ==='); 