# rust-tpm2-file-encryption-example
An example of symmetric file encryption and decryption in rust using rust-tss-esapi

## Development (into devcontainer)

The dev container should start and configure a software TPM, and build and install the tss library from scratch.

`cargo run` to encrypt file.txt to file.txt.tpmp (TPM Protected) encrypted file.
`cargo run -- --decrypt` to decrypt back file.txt.tpmp to std out.
`./test.sh` to run both commands.

## Build

To use the built executable outside of the dev container, with the real TPM of the device, install the needed shared librairies with (debian/ubuntu) : `sudo apt install libtss2-tctildr0`.
Then :
- to encrypt `sudo TCTI=device:/dev/tpmrm0 ./rust-tpm2-file-encryption-example`, a file named file.txt must be present as encryption target ;
- to decrypt `sudo TCTI=device:/dev/tpmrm0 ./rust-tpm2-file-encryption-example --decrypt` .