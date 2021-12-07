import { KMSClientConfig } from '@aws-sdk/client-kms';

export type KeyEncryptionKeyConfig = AWSKeyEncryptionKeyConfig;

export interface AWSKeyEncryptionKeyConfig extends KMSClientConfig {
    /**
     * The Amazon Resource Name (ARN) to the AWS customer master key (CMK)
     */
    arn?: string;

    /**
     * The AWS ID of the CMK
     */
    keyId?: string;
}