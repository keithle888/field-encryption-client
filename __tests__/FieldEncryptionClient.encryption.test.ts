import * as crypto from 'crypto';
import {DataEncryptionKey, FieldEncryptionClient} from "../src";
import {AES_GCM_256_KEY_LENGTH} from "../src/crypto/crypto";

const dek: DataEncryptionKey = {
    keyMaterial: crypto.randomBytes(AES_GCM_256_KEY_LENGTH),
    keyMaterialEnc: crypto.randomBytes(AES_GCM_256_KEY_LENGTH),
};
const plaintext = Buffer.from('a plaintext string', 'utf-8');

test('Encrypt & decrypt a payload', () => {
    expect(
      FieldEncryptionClient.decrypt(
        FieldEncryptionClient.encrypt(plaintext, dek),
            dek
        )
    ).toStrictEqual(plaintext);
});

test('Encrypt & decrypt a payload with the different key should yield an error', () => {
    const aDiffKey: DataEncryptionKey = {
        keyMaterial: crypto.randomBytes(AES_GCM_256_KEY_LENGTH),
        keyMaterialEnc: crypto.randomBytes(AES_GCM_256_KEY_LENGTH),
    };

    expect(
        () => {
            FieldEncryptionClient.decrypt(
              FieldEncryptionClient.encrypt(plaintext, dek),
                aDiffKey
            ).toString('utf-8');
        }
    ).toThrow();
});

