const { generateMnemonicPhrase, generateKeyPairFromMnemonic, generateKeyPair, sign, verify, encrypt, decrypt } = require('./index.js');

// Test message
const message = 'Hello, this is a test message!';

async function runTests() {
    console.log('=== Starting VeriCrypt Test ===\n');

    // Test 1: Generate mnemonic
    console.log('1. Generating mnemonic phrase...');
    const mnemonic = generateMnemonicPhrase();
    console.log('   Mnemonic:', mnemonic);
    console.log('   ✅ Mnemonic generated successfully!\n');

    // Test 2: Generate key pairs from mnemonic
    console.log('2. Generating key pairs from mnemonic...');
    const senderKeysFromMnemonic = generateKeyPairFromMnemonic(mnemonic);
    console.log('   Sender Signing Public Key:', senderKeysFromMnemonic.signingPublicKey.substring(0, 20) + '...');
    console.log('   Sender Encryption Public Key:', senderKeysFromMnemonic.encryptionPublicKey.substring(0, 20) + '...');
    console.log('   ✅ Key pairs generated from mnemonic!\n');

    // Test 3: Generate random key pairs
    console.log('3. Generating random key pairs...');
    const senderKeys = generateKeyPair();
    const receiverKeys = generateKeyPair();
    console.log('   Sender Signing Public Key:', senderKeys.signingPublicKey.substring(0, 20) + '...');
    console.log('   Sender Encryption Public Key:', senderKeys.encryptionPublicKey.substring(0, 20) + '...');
    console.log('   Receiver Encryption Public Key:', receiverKeys.encryptionPublicKey.substring(0, 20) + '...\n');

    // Test 4: Sign the message
    console.log('4. Signing the message...');
    const signedData = await sign(message, senderKeys.signingPrivateKey);
    console.log('   Original Message:', signedData.message);
    console.log('   Signature:', signedData.signature.substring(0, 20) + '...\n');

    // Test 5: Verify the signature
    console.log('5. Verifying the signature...');
    const isValid = await verify(signedData, senderKeys.signingPublicKey);
    console.log('   Signature is valid:', isValid);
    if (!isValid) {
        console.error('   ❌ Signature verification failed!');
        process.exit(1);
    }
    console.log('   ✅ Signature verification successful!\n');

    // Test 6: Encrypt the message
    console.log('6. Encrypting the message...');
    const encryptedData = encrypt(signedData.message, receiverKeys.encryptionPublicKey);
    console.log('   Encrypted Message:', encryptedData.encryptedMessage.substring(0, 20) + '...');
    console.log('   Ephemeral Public Key:', encryptedData.ephemeralPublicKey.substring(0, 20) + '...\n');

    // Test 7: Decrypt the message
    console.log('7. Decrypting the message...');
    const decryptedMessage = decrypt(encryptedData, receiverKeys.encryptionPrivateKey);
    if (!decryptedMessage) {
        console.error('   ❌ Decryption failed!');
        process.exit(1);
    }
    console.log('   Decrypted Message:', decryptedMessage);
    console.log('   ✅ Decryption successful!\n');

    // Test 8: Verify the decrypted message matches the original
    console.log('8. Verifying the decrypted message...');
    if (decryptedMessage === message) {
        console.log('   ✅ Decrypted message matches the original message!');
    } else {
        console.error('   ❌ Decrypted message does not match the original message!');
        process.exit(1);
    }

    console.log('\n=== All tests completed successfully! ===');
}

// Run the tests
runTests().catch(error => {
    console.error('Test failed:', error);
    process.exit(1);
}); 