import {connect, connection, disconnect} from 'mongoose';
import { GenerateDataKeyResponse } from '@aws-sdk/client-kms';
import * as crypto from 'crypto';
import { Types } from 'mongoose';
import {FieldEncryptionClient} from "../src";
import {MongoMemoryServer} from "mongodb-memory-server";

let client: FieldEncryptionClient;
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

let mongod: MongoMemoryServer;

beforeAll(async () => {
    mongod = await MongoMemoryServer.create();
    await connect(mongod.getUri());
    client = new FieldEncryptionClient(connection, { keyId: '' }, { keyVaultName: '__keyVault' });
});

afterAll(async () => {
    await disconnect();
    await mongod.stop();
});

test('createDataKey() creates a data key and saves into MongoDB', async () => {
    const dek = await client.createDataKey();
    const dekModel = client.getDataKeyMongooseModel();
    const mongoDek = await dekModel.findOne({ _id: new Types.ObjectId(dek.keyId) });
    expect(dek.keyId).toEqual(mongoDek._id.toString());
    expect(dek.keyMaterial).toStrictEqual(mockResponse.Plaintext);
    expect(mockResponse.CiphertextBlob).toStrictEqual(Buffer.from(mongoDek.keyMaterial, 'base64'));
});

