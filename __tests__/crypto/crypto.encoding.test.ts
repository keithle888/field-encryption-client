import * as crypto from '../../src/crypto/crypto';

test('encode & decode value matches, without aead', () => {
    const ciphertext = Buffer.from('aaaaaa', 'hex');
    const authTag = Buffer.from('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'hex');
    const iv = Buffer.from('cccccccccccccccccccccccccccccccc', 'hex');

    expect(
        crypto.decodeCipher(
            crypto.encodeCipher(ciphertext, authTag, iv)
        )
    ).toStrictEqual(
        { ciphertext, authTag, iv, aead: undefined }
    );
});

test('encode & decode value matches, with aead', () => {
    const ciphertext = Buffer.from('aaaaaa', 'hex');
    const authTag = Buffer.from('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'hex');
    const iv = Buffer.from('cccccccccccccccccccccccccccccccc', 'hex');
    const aead = Buffer.from('aead', 'utf-8');

    expect(
        crypto.decodeCipher(
            crypto.encodeCipher(ciphertext, authTag, iv, aead)
        )
    ).toStrictEqual(
        { ciphertext, authTag, iv, aead }
    );
});