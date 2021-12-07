import { Connection, Model, Types } from 'mongoose';
import { KeyEncryptionKeyConfig } from './models/KeyEncryptionKey';
import { DataEncryptionKey, DataEncryptionKeyConfig, DataEncryptionKeySchema, MongooseDEK } from './models/DataEncryptionKey';
import { DataKeySpec, DecryptCommand, GenerateDataKeyCommand, KMSClient } from '@aws-sdk/client-kms';
import { AES_GCM_256_IV_LENGTH, decodeCipher, decryptAES256GCM, encodeCipher, encryptAES256GCM } from './crypto/crypto';
import * as crypto from 'crypto';

export class FieldEncryptionClient {
    private connection: Connection;
    private kekConfig: KeyEncryptionKeyConfig;
    private awsKmsClient: KMSClient;
    private dekConfig: DataEncryptionKeyConfig;
    private dekModel: Model<MongooseDEK>;

    /**
     * @param connection The connection to mongoose. Assumes it is already connected.
     * @param kekConfig Configuration to KEK/Master Key in AWS KMS
     * @param dekConfig Configuration for MongoDB to store the data keys.
     */
    constructor(
        connection: Connection,
        kekConfig: KeyEncryptionKeyConfig,
        dekConfig: DataEncryptionKeyConfig
    ) {
        // Some data validation
        if (kekConfig.keyId == undefined
            && kekConfig.arn == undefined) {
            throw new Error('Either AWS CMK keyId or ARN must be defined');
        }

        this.connection = connection;
        this.kekConfig = kekConfig;
        this.awsKmsClient = new KMSClient(kekConfig);
        this.dekConfig = dekConfig;
        this.dekModel = this.connection.model(this.dekConfig.keyVaultName, DataEncryptionKeySchema, this.dekConfig.keyVaultName);
    }

    /**
     * Encrypt a field based on a DEK provided
     * @param field
     * @param dek
     */
    static encrypt(field: Buffer, dek: DataEncryptionKey): string {
        // Encrypt field
        const cipher = encryptAES256GCM(
            field,
            dek.keyMaterial,
            crypto.randomBytes(AES_GCM_256_IV_LENGTH), // TODO("IV used should be unique instead of using a random generator. A random generator is used in place of finding a suitable cryptographic function to save time. And is not viewed at the time of writing to be a major issue.")
            Buffer.from(dek.keyId, 'utf8') // Attach keyId as AEAD to help diagnose decryption errors.
        );

        // Encode field
        return encodeCipher(
            cipher.ciphertext,
            cipher.authTag,
            cipher.iv,
            cipher.aead
        );
    }

    /**
     * Decrypt a field. The data key will be retrieved based on the data-key & key-encryption-key config
     * @param field
     * @param dek
     */
    static decrypt(field: string, dek: DataEncryptionKey): Buffer {
        // Get DEK key ID from aead.
        const decodedField = decodeCipher(field);

        try {
            return decryptAES256GCM(
                decodedField.ciphertext,
                decodedField.authTag,
                dek.keyMaterial,
                decodedField.iv,
                decodedField.aead
            );
        } catch (error) {
            if (decodedField.aead !== undefined
                && decodedField.aead.toString('utf8') !== dek.keyId) {
                throw new Error('Error during decryption. Mismatched ID between argument DEK and DEK used to encrypt payload.');
            }
            throw error;
        }
    }

    /**
     * Retrieve a data key from the database and decrypt it.
     * @param id
     */
    async getDataKey(id: string): Promise<DataEncryptionKey> {
        // Attempt to find key from collection.
        const encryptedDek = await this.dekModel.findOne({ _id: new Types.ObjectId(id) });

        if (encryptedDek == undefined) throw new Error('Data key could not be found');

        // Decrypt key with KEK config
        const decryptedDek = await this.awsKmsClient.send(new DecryptCommand({
            KeyId: this.kekConfig.arn ?? this.kekConfig.keyId,
            CiphertextBlob: Buffer.from(encryptedDek.keyMaterial, 'base64')
        }));

        return {
            keyMaterial: Buffer.from(decryptedDek.Plaintext!),
            keyId: encryptedDek._id.toString(),
        };
    }

    /**
     * Create a data key and store it in the database based on the DataEncryptionKeyConfig
     */
    async createDataKey(): Promise<DataEncryptionKeyConfig & DataEncryptionKey> {
        const dekModel = this.getDataKeyMongooseModel();
        // If no key is found, create new key & save to database.
        const generatedDek = await this.awsKmsClient.send(new GenerateDataKeyCommand({
            KeyId: this.kekConfig.arn ?? this.kekConfig.keyId,
            KeySpec: DataKeySpec.AES_256
        }));

        const savedDek = await dekModel.create({
            keyMaterial: Buffer.from(generatedDek.CiphertextBlob!).toString('base64')
        });

        return {
            keyId: savedDek._id.toString(),
            keyVaultName: this.dekConfig.keyVaultName,
            keyMaterial: Buffer.from(generatedDek.Plaintext!)
        };
    }

    getDataKeyMongooseModel(): Model<any> { // TODO('How to fix the any generic')
        return this.connection.models['DataEncryptionKey']
            ?? this.connection.model<DataEncryptionKey>('DataEncryptionKey', DataEncryptionKeySchema, this.dekConfig.keyVaultName);
    }
}