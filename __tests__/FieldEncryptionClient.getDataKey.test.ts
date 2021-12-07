import {connect, connection, disconnect} from 'mongoose';
import * as crypto from 'crypto';
import { Document } from 'mongoose';
import { GenerateDataKeyResponse } from '@aws-sdk/client-kms';
import {FieldEncryptionClient, MongooseDEK} from "../src";
import {MongoMemoryServer} from "mongodb-memory-server";
import {AES_GCM_256_KEY_LENGTH} from "../src/crypto/crypto";

let client: FieldEncryptionClient;
let dek: Document<MongooseDEK>;

// region mock-kms
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
// endregion mock-kms

let mongod: MongoMemoryServer;

beforeAll(async () => {
    mongod = await MongoMemoryServer.create();
    await connect(mongod.getUri());
    client = new FieldEncryptionClient(connection, { keyId: '' }, { keyVaultName: '__keyVault' });
    // Inject a single DataEncryptionKey
    dek = await client.getDataKeyMongooseModel().create({
        keyMaterial: crypto.randomBytes(AES_GCM_256_KEY_LENGTH)
    });
});

afterAll(async () => {
    await disconnect();
    await mongod.stop();
});

test('getDataKey() gets a data key when it is present in MongoDB', async () => {
    expect(await client.getDataKey(dek._id!.toString())).toBeDefined();
});

test('getDataKey() to throw when no data key is matched in MongoDB', () => {
    const randomId = crypto.randomBytes(12).toString('hex');

    return expect(client.getDataKey(randomId))
        .rejects
        .toEqual(expect.any(Error));
});