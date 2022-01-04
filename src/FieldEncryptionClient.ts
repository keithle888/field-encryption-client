import { KeyEncryptionKeyConfig } from './models/KeyEncryptionKey';
import { DataEncryptionKey } from './models/DataEncryptionKey';
import { DataKeySpec, DecryptCommand, GenerateDataKeyCommand, KMSClient } from '@aws-sdk/client-kms';
import { AES_GCM_256_IV_LENGTH, decodeCipher, decryptAES256GCM, encodeCipher, encryptAES256GCM } from './crypto/crypto';
import * as crypto from 'crypto';

export class FieldEncryptionClient {
    private kekConfig: KeyEncryptionKeyConfig;
    private awsKmsClient: KMSClient;

    /**
     * @param kekConfig Configuration to KEK/Master Key in AWS KMS
     */
    constructor(
        kekConfig: KeyEncryptionKeyConfig,
    ) {
        // Some data validation
        if (kekConfig.keyId == undefined
            && kekConfig.arn == undefined) {
            throw new Error('Either AWS CMK keyId or ARN must be defined');
        }

        this.kekConfig = kekConfig;
        this.awsKmsClient = new KMSClient(kekConfig);
    }

    /**
     * Encrypt a field based on a DEK provided
     * @param field field as a buffer
     * @param dek Data encryption key
     * @param algo Algorithm to encrypt the field with.
     */
    static encrypt(field: Buffer, dek: DataEncryptionKey, algo: 'AES-256-GCM-WITHOUT-AEAD' = 'AES-256-GCM-WITHOUT-AEAD'): Buffer {
        // Encrypt field
        const cipher = encryptAES256GCM(
            field,
            dek.keyMaterial,
            crypto.randomBytes(AES_GCM_256_IV_LENGTH), // TODO("IV used should be unique instead of using a random generator. A random generator is used in place of finding a suitable cryptographic function to save time. And is not viewed at the time of writing to be a major issue.")
            undefined
        );

        // Encode field
        return encodeCipher(
            cipher.ciphertext,
            cipher.authTag,
            cipher.iv
        );
    }

    /**
     * Decrypt a field. The data key will be retrieved based on the data-key & key-encryption-key config
     * @param field
     * @param dek
     * @param algo Algorithm to decrypt the field with.
     */
    static decrypt(field: Buffer, dek: DataEncryptionKey, algo: 'AES-256-GCM-WITHOUT-AEAD' = 'AES-256-GCM-WITHOUT-AEAD'): Buffer {
        // Get DEK key ID from aead.
        const decodedField = decodeCipher(field);

        return decryptAES256GCM(
            decodedField.ciphertext,
            decodedField.authTag,
            dek.keyMaterial,
            decodedField.iv
        );
    }

    /**
     * Retrieve a data key from the database and decrypt it.
     * @param encryptedDek encrypted Data Key material
     */
    async getDataKey(encryptedDek: Buffer): Promise<DataEncryptionKey> {
        if (encryptedDek.length === 0) throw new Error('Provided DEK material is empty.')

        const eDekDup = Buffer.alloc(encryptedDek.length);
        encryptedDek.copy(eDekDup);

        // Decrypt key with KEK config
        const decryptedDek = await this.awsKmsClient.send(new DecryptCommand({
            KeyId: this.kekConfig.arn ?? this.kekConfig.keyId,
            CiphertextBlob: eDekDup
        }));

        return {
            keyMaterial: Buffer.from(decryptedDek.Plaintext!),
            keyMaterialEnc: eDekDup,
        };
    }

    /**
     * Create a data key and store it in the database based on the DataEncryptionKeyConfig
     */
    async createDataKey(): Promise<DataEncryptionKey> {
        const generatedDek = await this.awsKmsClient.send(new GenerateDataKeyCommand({
            KeyId: this.kekConfig.arn ?? this.kekConfig.keyId,
            KeySpec: DataKeySpec.AES_256
        }));

        return {
            keyMaterial: Buffer.from(generatedDek.Plaintext!),
            keyMaterialEnc: Buffer.from(generatedDek.CiphertextBlob!)
        };
    }
}