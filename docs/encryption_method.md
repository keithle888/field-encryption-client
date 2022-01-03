## Encryption Method
The AES-256-GCM scheme is chosen because:
- It is supported on node’s crypto library, OpenSSL (as of 1.0.1c?) & LibreSSL.
- Is an AEAD cipher which is useful for validating meta-data that can be stored in plain text alongside the ciphertext without security leaks.
- A symmetric encryption method is faster than asymmetric and is used by default in CSFLE flows.
- The necessary parameters for decryption can be stored alongside the cipher text (except the cipher key obviously).

## Encoding
Once a field has been encrypted, the necessary parameters need to be encoded alongside the ciphertext to provide a single output that can be efficiently stored.

The output values (same values needed for decryption) from an AES-256-GCM process is:
- cipher text: encrypted version of the sensitive field
- auth tag: a 16-byte field that is used authenticate the cipher text with the cipher key before decryption occurs
- iv: randomly generated initialization value that must not be repeated.

The final payload can be the individual components concatenated together in the format:
```
<cipher text><auth tag><iv>
```