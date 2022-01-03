
import * as crypto from 'crypto';
import { GenerateDataKeyResponse } from '@aws-sdk/client-kms';
import {FieldEncryptionClient} from "../src";
import {AES_GCM_256_KEY_LENGTH} from "../src/crypto/crypto";

// region mock-kms
const mockResponse: GenerateDataKeyResponse = { // variable must start with 'mock'
    Plaintext: crypto.randomBytes(AES_GCM_256_KEY_LENGTH),
};
jest.mock('@aws-sdk/client-kms', () => { // Mocks '@aws-sdk/client-kms' module
    return {
        ...jest.requireActual('@aws-sdk/client-kms'), // Require actual for all enums & predefined values
        KMSClient: jest.fn(() => { // Mocks KMSClient constructor
            return {
                send: jest.fn().mockResolvedValue(mockResponse) // Mocks send()
            };
        })
    };
});
// endregion mock-kms

let client: FieldEncryptionClient = new FieldEncryptionClient({ keyId: '' });

test('getDataKey() calls AWS API to decrypt DEK', async () => {
    const eDek = crypto.randomBytes(AES_GCM_256_KEY_LENGTH);
    const dek = await client.getDataKey(eDek);
    expect(dek.keyMaterial).toStrictEqual(mockResponse.Plaintext);
    expect(dek.keyMaterialEnc).toStrictEqual(eDek);
});

test('getDataKey() to throw when empty data key provided', () => {
    const key = crypto.randomBytes(0)

    return expect(client.getDataKey(key))
        .rejects
        .toEqual(expect.any(Error));
});