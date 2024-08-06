use bincode::{config, Decode, Encode};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::AeadCore;
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::KeyInit;
use chacha20poly1305::Nonce;
use core::str;
use std::env;
use std::fs;
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::structures::Data;
use tss_esapi::structures::HashScheme;
use tss_esapi::structures::PublicKeyRsa;
use tss_esapi::structures::PublicRsaParametersBuilder;
use tss_esapi::structures::RsaDecryptionScheme;
use tss_esapi::structures::RsaExponent;
use tss_esapi::structures::RsaScheme;
use tss_esapi::structures::{Private, Public};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::{
    attributes::ObjectAttributesBuilder,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        resource_handles::Hierarchy,
    },
    structures::{
        CreatePrimaryKeyResult, Digest, PublicBuilder, SymmetricCipherParameters,
        SymmetricDefinitionObject,
    },
    Context, TctiNameConf,
};

const PLAIN_FILE_NAME: &str = "file.txt";
const ENCRYPTED_FILE_NAME: &str = "file.txt.tpmp";

fn main() {
    // Create a new TPM context. This reads from the environment variable `TPM2TOOLS_TCTI` or `TCTI`
    //
    // It's recommended you use `TCTI=device:/dev/tpmrm0` for the linux kernel
    // tpm resource manager.
    let context = Context::new(
        TctiNameConf::from_environment_variable()
            .expect("Failed to get TCTI / TPM2TOOLS_TCTI from environment. Try `export TCTI=device:/dev/tpmrm0`"),
    )
    .expect("Failed to create Context");

    let should_decrypt = env::args().nth(1).is_some_and(|a| a == "--decrypt");
    if should_decrypt {
        let decrypted_data = decrypt(context);
        let initial_data = fs::read(PLAIN_FILE_NAME).expect("could not read plain file");
        println!(
            "=== Initial data ===\n\n{}\n\n\n\n",
            str::from_utf8(&initial_data).expect("could not convert initial data to UTF-8 string")
        );
        print!("");
        println!(
            "=== Decrypted data ===\n\n{}",
            str::from_utf8(&decrypted_data)
                .expect("could not convert decrypted data to UTF-8 string")
        );
        // They are the same!
        assert_eq!(initial_data, decrypted_data);
    } else {
        encrypt(context);
    }
}

#[derive(Encode, Decode, PartialEq, Debug)]
struct BinaryEncryptedBundle {
    encrypted_data: Vec<u8>,
    encrypted_symmetric_key: Vec<u8>,
    tpm_public_key: Vec<u8>,
    tpm_private_key: Vec<u8>,
    nonce: Vec<u8>,
}

#[derive(PartialEq, Debug)]
pub struct EncryptedBundle {
    encrypted_data: Vec<u8>,
    encrypted_symmetric_key: PublicKeyRsa,
    tpm_public_key: Public,
    tpm_private_key: Private,
    nonce: Nonce,
}

impl EncryptedBundle {
    fn from_file(path: &str) -> Self {
        let config = config::standard();
        let encrypted_bundle_file = fs::read(path).expect("could not open encrypted data file");
        let (binary_encrypted_bundle, _): (BinaryEncryptedBundle, usize) =
            bincode::decode_from_slice(&encrypted_bundle_file[..], config)
                .expect("could not get the binary encrypted bundle from file");
        Self {
            encrypted_data: binary_encrypted_bundle.encrypted_data,
            encrypted_symmetric_key: PublicKeyRsa::from_bytes(
                &binary_encrypted_bundle.encrypted_symmetric_key,
            )
            .expect("could not unmarshall encrypted symmetric key"),
            tpm_public_key: Public::unmarshall(&binary_encrypted_bundle.tpm_public_key)
                .expect("could not unmarshall public key"),
            tpm_private_key: Private::unmarshall(&binary_encrypted_bundle.tpm_private_key)
                .expect("could not unmarshall private key"),
            nonce: *Nonce::from_slice(&binary_encrypted_bundle.nonce),
        }
    }

    fn dump_to_file(self, path: &str) {
        let config = config::standard();
        let binary_encrypted_bundle = BinaryEncryptedBundle {
            encrypted_data: self.encrypted_data,
            encrypted_symmetric_key: self.encrypted_symmetric_key.to_vec(),
            tpm_public_key: self
                .tpm_public_key
                .marshall()
                .expect("could not marshall public key"),
            tpm_private_key: self
                .tpm_private_key
                .marshall()
                .expect("could not marshall private key"),
            nonce: self.nonce.as_slice().to_vec(),
        };
        let encrypted_bundle_file = bincode::encode_to_vec(binary_encrypted_bundle, config)
            .expect("could not encode EncryptedData to binary");
        fs::write(path, encrypted_bundle_file).expect("could not create encrypted file");
    }
}

fn encrypt(mut context: Context) {
    // This example won't go over the process to create a new parent. For more detail see `examples/hmac.rs`.
    let primary = create_primary(&mut context);

    // Begin to create our new RSA key.
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_st_clear(false)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        // We need a key that can decrypt values - we don't need to worry
        // about signatures.
        .with_decrypt(true)
        // Note that we don't set the key as restricted.
        .build()
        .expect("Failed to build object attributes");

    let rsa_params = PublicRsaParametersBuilder::new()
        // The value for scheme may have requirements set by a combination of the
        // sign, decrypt, and restricted flags. For an unrestricted signing and
        // decryption key then scheme must be NULL. For an unrestricted decryption key,
        // NULL, OAEP or RSAES are valid for use.
        .with_scheme(RsaScheme::Null)
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .with_is_decryption_key(true)
        // We don't require signatures, but some users may.
        // .with_is_signing_key(true)
        .with_restricted(false)
        .build()
        .expect("Failed to build rsa parameters");

    let key_pub = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .expect("could not configure TPM public key");

    let (private, public) = context
        .execute_with_nullauth_session(|ctx| {
            ctx.create(primary.key_handle, key_pub, None, None, None, None)
                .map(|key| (key.out_private, key.out_public))
        })
        .expect("could not create TPM child key");

    // We generate a ChaCha20Poly1305 key that will be used outside of the TPM to encrypt the data (since Intel PTT cannot do EncryptDecrypt(2))
    let chacha_key = ChaCha20Poly1305::generate_key(&mut OsRng);
    // We generate a nonce that should be persisted as well for decoding
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    let key_to_encrypt = PublicKeyRsa::try_from(chacha_key.to_vec())
        .expect("failed to create buffer for key to encrypt");

    // We encrypt the key with the TPM
    let encrypted_symmetric_key = context
        .execute_with_nullauth_session(|ctx| {
            let rsa_pub_key = ctx
                .load_external_public(public.clone(), Hierarchy::Null)
                .expect("could not load child key into TPM context");

            ctx.rsa_encrypt(
                rsa_pub_key,
                key_to_encrypt.clone(),
                RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
                Data::default(),
            )
        })
        .expect("could not encrypt symmetric key with TPM");

    // We load the data from a file system file, it can be somewhat large (like a certificate)
    let initial_data = fs::read(PLAIN_FILE_NAME).expect("could not open data file");

    // We encrypt the data
    let cipher = ChaCha20Poly1305::new(&chacha_key);
    let encrypted_data = cipher
        .encrypt(&nonce, initial_data.as_ref())
        .expect("could not encrypt data");

    // Persist the encrypted data, the keys, and the IV for later decryption
    let persisted_data = EncryptedBundle {
        encrypted_data,
        encrypted_symmetric_key,
        tpm_public_key: public,
        tpm_private_key: private,
        nonce,
    };
    persisted_data.dump_to_file(ENCRYPTED_FILE_NAME);
}

fn decrypt(mut context: Context) -> Vec<u8> {
    // This example won't go over the process to create a new parent. For more detail see `examples/hmac.rs`.
    let primary = create_primary(&mut context);

    // Load the EncryptedBundle
    let encrypted_bundle = EncryptedBundle::from_file(ENCRYPTED_FILE_NAME);

    // Get the chacha20poly1305 key from TPM encrypted data
    let chacha_key = context
        .execute_with_nullauth_session(|ctx| {
            let rsa_priv_key = ctx
                .load(
                    primary.key_handle,
                    encrypted_bundle.tpm_private_key,
                    encrypted_bundle.tpm_public_key,
                )
                .expect("could not load TPM child key into context");

            ctx.rsa_decrypt(
                rsa_priv_key,
                encrypted_bundle.encrypted_symmetric_key,
                RsaDecryptionScheme::Oaep(HashScheme::new(HashingAlgorithm::Sha1)),
                Data::default(),
            )
        })
        .expect("could not decrypt symmetric key from TPM encrypted key");

    // Decryt the data using the key
    let cipher = ChaCha20Poly1305::new(chacha_key.as_bytes().into());
    cipher
        .decrypt(
            &encrypted_bundle.nonce,
            encrypted_bundle.encrypted_data.as_ref(),
        )
        .expect("could not decipher chacha20poly1305 encrypted data")
}

fn create_primary(context: &mut Context) -> CreatePrimaryKeyResult {
    // Create the primary key. A primary key is the "root" of a collection of objects.
    // These other objects are encrypted by the primary key allowing them to persist
    // over a reboot and reloads.
    //
    // A primary key is derived from a seed, and provided that the same inputs are given
    // the same primary key will be derived in the tpm. This means that you do not need
    // to store or save the details of this key - only the parameters of how it was created.
    let object_attributes = ObjectAttributesBuilder::new()
        // Indicate the key can only exist within this tpm and can not be exported.
        .with_fixed_tpm(true)
        // The primary key and it's descendent keys can't be moved to other primary
        // keys.
        .with_fixed_parent(true)
        // The primary key will persist over suspend and resume of the system.
        .with_st_clear(false)
        // The primary key was generated entirely inside the TPM - only this TPM
        // knows it's content.
        .with_sensitive_data_origin(true)
        // This key requires "authentication" to the TPM to access - this can be
        // an HMAC or password session. HMAC sessions are used by default with
        // the "execute_with_nullauth_session" function.
        .with_user_with_auth(true)
        // This key has the ability to decrypt
        .with_decrypt(true)
        // This key may only be used to encrypt or sign objects that are within
        // the TPM - it can not encrypt or sign external data.
        .with_restricted(true)
        .build()
        .expect("Failed to build object attributes");

    let primary_pub = PublicBuilder::new()
        // This key is a symmetric key.
        .with_public_algorithm(PublicAlgorithm::SymCipher)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_symmetric_cipher_parameters(SymmetricCipherParameters::new(
            SymmetricDefinitionObject::AES_128_CFB,
        ))
        .with_symmetric_cipher_unique_identifier(Digest::default())
        .build()
        .expect("could not configure TPM primary key");

    context
        .execute_with_nullauth_session(|ctx| {
            // Create the key under the "owner" hierarchy. Other hierarchies are platform
            // which is for boot services, null which is ephemeral and resets after a reboot,
            // and endorsement which allows key certification by the TPM manufacturer.
            ctx.create_primary(Hierarchy::Owner, primary_pub, None, None, None, None)
        })
        .expect("could not create TPM primary key")
}
