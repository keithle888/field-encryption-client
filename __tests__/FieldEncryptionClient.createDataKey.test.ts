import { GenerateDataKeyResponse } from '@aws-sdk/client-kms';
import * as crypto from 'crypto';
import {FieldEncryptionClient} from "../src";

// Mock AWS KMS Client
const mockResponse: GenerateDataKeyResponse = { // variable must start with 'mock'
    CiphertextBlob: crypto.randomBytes(32),
    Plaintext: crypto.randomBytes(32),
    KeyId: undefined
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

let client = new FieldEncryptionClient({ keyId: '' });

test('createDataKey() creates a data key and saves into MongoDB', async () => {
    const dek = await client.createDataKey();
    expect(dek.keyMaterial).toStrictEqual(mockResponse.Plaintext);
    expect(dek.keyMaterialEnc).toStrictEqual(mockResponse.CiphertextBlob);
});

