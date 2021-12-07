import * as crypto from '../../src/crypto/crypto';

const AES_KEY = Buffer.from('2b7e151628aed2a6abf715892b7e151628aed2a6abf715892b7e151628aed2a6', 'hex'); // 32 bytes
const IV = Buffer.from('00010203040566334433441122332255'); // 16 bytes

test('plaintext encrypted with AES-256-GCM is correct', () => {
    const { ciphertext, authTag } = crypto.encryptAES256GCM(
        Buffer.from('a string', 'utf-8'),
        AES_KEY,
        IV
    );
    expect(ciphertext).toStrictEqual(Buffer.from('3APxtRt5Lgw=', 'base64'));
    expect(authTag).toStrictEqual(Buffer.from('1tNGU8jGRQVRUcqXX4Ppvw==', 'base64'));
});

test('ciphertext decrypted with AES-256-GCM is correct', () => {
    const dec = crypto.decryptAES256GCM(
        Buffer.from('3APxtRt5Lgw=', 'base64'),
        Buffer.from('1tNGU8jGRQVRUcqXX4Ppvw==', 'base64'),
        AES_KEY,
        IV
    );
    expect(dec.toString('utf-8')).toBe('a string');
});

test('ciphertext decrypted with wrong auth tag throws Error', () => {
    const decryFn = () => {
        crypto.decryptAES256GCM(
            Buffer.from('3APxtRt5Lgw=', 'base64'),
            Buffer.from('1tNGU8AGRQVRUcqXX4Ppvw==', 'base64'),
            AES_KEY,
            IV
        );
    };
    expect(decryFn).toThrow();
});

test('plaintext & aead encrypted with AES-256-GCM is correct', () => {
    const { ciphertext, authTag } = crypto.encryptAES256GCM(
        Buffer.from('a string', 'utf-8'),
        AES_KEY,
        IV,
        Buffer.from('aead', 'utf-8')
    );
    expect(ciphertext).toStrictEqual(Buffer.from('3APxtRt5Lgw=', 'base64'));
    expect(authTag).toStrictEqual(Buffer.from('sNlHGSbnk/vQ7IQW5nVMfA==', 'base64'));
});

test('ciphertext decrypted with wrong aead throws Error', () => {
    const decryFn = () => {
        crypto.decryptAES256GCM(
            Buffer.from('3APxtRt5Lgw=', 'base64'),
            Buffer.from('sNlHGSbnk/vQ7IQW5nVMfA==', 'base64'),
            AES_KEY,
            IV,
            Buffer.from('aeadb', 'utf-8')
        );
    };
    expect(decryFn).toThrow();
});

test('ciphertext & aead decrypted with AES-256-GCM is correct', () => {
    const dec = crypto.decryptAES256GCM(
        Buffer.from('3APxtRt5Lgw=', 'base64'),
        Buffer.from('sNlHGSbnk/vQ7IQW5nVMfA==', 'base64'),
        AES_KEY,
        IV,
        Buffer.from('aead', 'utf-8')
    );
    expect(dec.toString('utf-8')).toBe('a string');
});


