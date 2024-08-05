# rust-tpm2-file-encryption-example
An example of symmetric file encryption and decryption in rust using rust-tss-esapi

## Usage

`cargo run` to encrypt file.txt to file.txt.tpmp (TPM Protected) encrypted file.
`cargo run -- --decrypt` to decrypt back file.txt.tpmp to std out.
`./test.sh` to run both commands.