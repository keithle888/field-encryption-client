export interface DataEncryptionKey {
    /**
     * Key material in plaintext
     */
    readonly keyMaterial: Buffer;

    /**
     * keyMaterial in encrypted form
     */
    readonly keyMaterialEnc: Buffer;
}
