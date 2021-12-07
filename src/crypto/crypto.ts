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
 * @param aead
 */
export function encodeCipher(ciphertext: Buffer, authTag: Buffer, iv: Buffer, aead?: Buffer): string {
    const enc = Buffer.alloc(ciphertext.length + authTag.length + iv.length);
    ciphertext.copy(enc);
    authTag.copy(enc, ciphertext.length);
    iv.copy(enc, ciphertext.length + authTag.length);
    if (aead === undefined) {
        return enc.toString('base64');
    }
    else {
        return `${enc.toString('base64')}.${aead.toString('base64')}`;
    }
}

/**
 * Decode cipher stored in the database into the individual cipher values
 * @param cipher
 */
export function decodeCipher(cipher: string): { ciphertext: Buffer, authTag: Buffer, iv: Buffer, aead?: Buffer } {
    const strs = cipher.split('.');
    let aead: Buffer | undefined = undefined;
    const cBuf = Buffer.from(strs[0], 'base64');
    const ciphertextLength = cBuf.length - (AES_GCM_256_AUTH_TAG_LENGTH + AES_GCM_256_IV_LENGTH);
    const ciphertext = Buffer.alloc(ciphertextLength);
    const authTag = Buffer.alloc(AES_GCM_256_AUTH_TAG_LENGTH);
    const iv = Buffer.alloc(AES_GCM_256_IV_LENGTH);
    cBuf.copy(ciphertext, 0, 0, ciphertextLength);
    cBuf.copy(authTag, 0, ciphertextLength, ciphertextLength + AES_GCM_256_AUTH_TAG_LENGTH);
    cBuf.copy(iv, 0, ciphertextLength + AES_GCM_256_AUTH_TAG_LENGTH);
    if (strs.length > 1) aead = Buffer.from(strs[1], 'base64');
    return { ciphertext, authTag, iv, aead };
}
