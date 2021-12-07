# field-encryption-client
This is an NPM package that simplifies client-side field encryption on MongoDB. 
The library accepts a user-defined configuration for the Key Encryption Key (KEK) and manages the creation, store & automatic decryption/encryption of the Data Encryption Key (DEK) on a user-defined MongoDB replicate set.
The library also provides encryption & decryption functions for individual fields.

This library currently only supports AWS KMS KEK configurations, and uses AWS SDK v3.
This library also uses mongoose ODM library for interacting with the user-defined MongoDB replica set.

## Usage
### Environment/Setup
This project is designed to be run in an AWS Lambda environment. 
KMS should be hosted on the same AWS account, and the permissions can be configured via serverless:
```
provider:
    iamRoleStatements:  
        - Effect: "Allow"
          Action:
            - "kms:GenerateDataKey"
            - "kms:Encrypt"
            - "kms:Decrypt"
          Resource:
            - "YourKeyARN"
```

### Getting started
Usage of the library stems from the class `FieldEncryptionClient`.
```
const client = new FieldEncryptionClient(
    mongoose.connection, // needs the connection being used to store the encrypted DEKs
    keyEncryptionKeyConfig, // configuration object for where the KEK is hosted
    dataEncryptionKeyConfig, // configuration object for how DEKs are stored in MongoDB
);
```

### Creation/Retrieval of DEK
Newly created DEKs are automatically encrypted with the KEK & saved into MongoDB.
Retrieved DEKs are automatically decrypted with the KEK.
```
// Creation
const dek = await client.createDataKey();

or

// Retrieval
const dek = await client.getDataKey(keyId); // keyId is provided when a DEK is created, and should be saved for retrieval later.
```

### Encryption & Decryption
```
// Encryption
const encryptedAsString = client.encrypt(fieldAsBuffer, dek);

// Decryption
const fieldAsBuffer = client.decrypt(encryptedAsString, dek);
```

## tsconfig.json
Some notes about the typescript configuration.
- `rootDir` - set to `./src`. All source code needs to be placed in the `./src` folder.
- `outDir` - the output directory of compiled files is set to the `./dist` folder.
- `exclude` - set to exclude all files in `./tests` from compilation. `ts-jest` will transpile them for jest.
