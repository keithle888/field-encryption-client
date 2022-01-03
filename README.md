# field-encryption-client
[![circleci](https://circleci.com/gh/keithle888/field-encryption-client.svg?style=shield)](https://circleci.com/gh/keithle888/field-encryption-client)

This package simplifies [client-side field encryption](https://www.mongodb.com/client-side-encryption) implementation to the point where the developer only needs to worry about encryption/decrypting field data & storing the encrypted data key (DEK).

*Note: This library currently only supports AWS KMS for the key-encryption-key (KEK) via AWS SDK v3.*

## Usage

### Getting started
Usage of the library stems from the class `FieldEncryptionClient`.
```
const client = new FieldEncryptionClient(
    kekConfig, // AWS KMS configuration
);
```

### Creation/Retrieval of DEK
Newly created DEKs are automatically encrypted with the KEK
Retrieved DEKs are automatically decrypted with the KEK.
```
// Create a new DEK (if one doesn't already exist)
const dek = await client.createDataKey();

or

// Retrieve & decrypt (when an existing DEK already exists)
const dek = await client.getDataKey(encryptedDek); // Decrypts the DEK with the kekConfig
```

### Encryption & Decryption
```
// Encryption
const encryptedAsBuffer = client.encrypt(fieldAsBuffer, dek);

// Decryption
const fieldAsBuffer = client.decrypt(encryptedAsBuffer, dek);
```