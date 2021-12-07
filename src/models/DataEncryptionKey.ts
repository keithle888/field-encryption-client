import { Schema } from 'mongoose';
import * as Mongoose from 'mongoose';

export interface DataEncryptionKeyConfig {
    /**
     * Collection name in mongoDB
     */
    keyVaultName: string;
}

export interface DataEncryptionKey {
    /**
     * Key material in plaintext
     */
    readonly keyMaterial: Buffer;

    /**
     * ID of the key.
     * For MongoDB stored versions, this will correspond to the _id of the document in hex.
     */
    readonly keyId: string;
}

/**
 * Interface for static typing mongoose schema
 */
export interface MongooseDEK {
    _id: Mongoose.Types.ObjectId;
    keyMaterial: string;
}

export const DataEncryptionKeySchema = new Schema<MongooseDEK>({
    keyMaterial: String,
});
