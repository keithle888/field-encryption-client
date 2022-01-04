// This file holds the basic crypto functions.

import * as crypto from 'crypto';

export const AES_GCM_256_AUTH_TAG_LENGTH = 16;
export const AES_GCM_256_IV_LENGTH = 16;
export const AES_GCM_256_KEY_LENGTH = 32;

export function encryptAES256GCM(plaintext: Buffer, cipherkey: Buffer, iv: Buffer, aead?: Buffer): { ciphertext: Buffer, authTag: Buffer, iv: Buffer, aead?: Buffer } {
    // iv should be 16 bytes
    const cipher = crypto.createCipheriv('aes-256-gcm', cipherkey, iv);
    if (aead !== undefined) cipher.setAAD(aead);
    const ciphertext = cipher.update(plaintext);
    cipher.final();
    const authTag = cipher.getAuthTag();
    return { ciphertext, authTag, iv, aead };
}

export function decryptAES256GCM(ciphertext: Buffer, authTag: Buffer, cipherkey: Buffer, iv: Buffer, aead?: Buffer): Buffer {
    const decipher = crypto.createDecipheriv('aes-256-gcm', cipherkey, iv);
    if (aead !== undefined) decipher.setAAD(aead);
    decipher.setAuthTag(authTag);
    const plain = decipher.update(ciphertext);
    decipher.final();
    return plain;
}

/**
 * Encode cipher values into a single string for storage into the database
 * @param ciphertext
 * @param authTag
 * @param iv
 */
export function encodeCipher(ciphertext: Buffer, authTag: Buffer, iv: Buffer): Buffer {
    const enc = Buffer.alloc(ciphertext.length + authTag.length + iv.length);
    ciphertext.copy(enc);
    authTag.copy(enc, ciphertext.length);
    iv.copy(enc, ciphertext.length + authTag.length);
    return enc;
}

/**
 * Decode cipher stored in the database into the individual cipher values
 * @param cipher
 */
export function decodeCipher(cipher: Buffer): { ciphertext: Buffer, authTag: Buffer, iv: Buffer } {
    const ciphertextLength = cipher.length - (AES_GCM_256_AUTH_TAG_LENGTH + AES_GCM_256_IV_LENGTH);
    const ciphertext = Buffer.alloc(ciphertextLength);
    const authTag = Buffer.alloc(AES_GCM_256_AUTH_TAG_LENGTH);
    const iv = Buffer.alloc(AES_GCM_256_IV_LENGTH);
    cipher.copy(ciphertext, 0, 0, ciphertextLength);
    cipher.copy(authTag, 0, ciphertextLength, ciphertextLength + AES_GCM_256_AUTH_TAG_LENGTH);
    cipher.copy(iv, 0, ciphertextLength + AES_GCM_256_AUTH_TAG_LENGTH);
    return { ciphertext, authTag, iv };
}
