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
use tss_esapi::attributes::NvIndexAttributes;
use tss_esapi::handles::NvIndexHandle;
use tss_esapi::handles::NvIndexTpmHandle;
use tss_esapi::interface_types::resource_handles::NvAuth;
use tss_esapi::interface_types::resource_handles::Provision;
use tss_esapi::structures::Auth;
use tss_esapi::structures::MaxNvBuffer;
use tss_esapi::structures::NvPublic;
use tss_esapi::{interface_types::algorithm::HashingAlgorithm, Context, TctiNameConf};

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
    key_size: u16,
    nv_index: u32,
    encrypted_data: Vec<u8>,
    nonce: Vec<u8>,
}

#[derive(PartialEq, Debug)]
pub struct EncryptedBundle {
    key_size: u16,
    nv_index: u32,
    encrypted_data: Vec<u8>,
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
            key_size: binary_encrypted_bundle.key_size,
            nv_index: binary_encrypted_bundle.nv_index,
            encrypted_data: binary_encrypted_bundle.encrypted_data,
            nonce: *Nonce::from_slice(&binary_encrypted_bundle.nonce),
        }
    }

    fn dump_to_file(self, path: &str) {
        let config = config::standard();
        let binary_encrypted_bundle = BinaryEncryptedBundle {
            key_size: self.key_size,
            nv_index: self.nv_index,
            encrypted_data: self.encrypted_data,
            nonce: self.nonce.as_slice().to_vec(),
        };
        let encrypted_bundle_file = bincode::encode_to_vec(binary_encrypted_bundle, config)
            .expect("could not encode EncryptedData to binary");
        fs::write(path, encrypted_bundle_file).expect("could not create encrypted file");
    }
}

fn encrypt(mut context: Context) {
    // We generate a ChaCha20Poly1305 key that will be used outside of the TPM to encrypt the data (since Intel PTT cannot do EncryptDecrypt(2))
    let chacha_key = ChaCha20Poly1305::generate_key(&mut OsRng);
    // We generate a nonce that should be persisted as well for decoding
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    let nv_index = context
        .execute_with_nullauth_session(|ctx| -> Result<NvIndexHandle, tss_esapi::Error> {
            let nv_index_handle = set_up_nv_space(ctx);

            let nv_stored_key = MaxNvBuffer::try_from(chacha_key.to_vec())
                .expect("Failed to create MaxNvBuffer from vec");

            // Use owner authorization
            ctx.nv_write(NvAuth::Owner, nv_index_handle, nv_stored_key, 0)
                .expect("call to nv_write failed");
            Ok(nv_index_handle)
        })
        .unwrap()
        .value();

    // We load the data from a file system file, it can be somewhat large (like a certificate)
    let initial_data = fs::read(PLAIN_FILE_NAME).expect("could not open data file");

    // We encrypt the data
    let cipher = ChaCha20Poly1305::new(&chacha_key);
    let encrypted_data = cipher
        .encrypt(&nonce, initial_data.as_ref())
        .expect("could not encrypt data");

    // Persist the encrypted data, the keys, and the IV for later decryption
    let persisted_data = EncryptedBundle {
        key_size: chacha_key.len() as u16,
        nv_index: nv_index,
        encrypted_data,
        nonce,
    };
    persisted_data.dump_to_file(ENCRYPTED_FILE_NAME);
}

fn decrypt(mut context: Context) -> Vec<u8> {
    // Load the EncryptedBundle
    let encrypted_bundle = EncryptedBundle::from_file(ENCRYPTED_FILE_NAME);

    let read_data = context
        .execute_with_nullauth_session(|ctx| {
            let nv_index_handle = NvIndexHandle::try_from(encrypted_bundle.nv_index)
                .expect("could not retrieve the nv handle trom TPM");

            // Get the chacha20poly1305 key from TPM non volatile stored value
            let nv_read_result = ctx.nv_read(
                NvAuth::Owner,
                nv_index_handle,
                encrypted_bundle.key_size.into(),
                0,
            );

            ctx.nv_undefine_space(Provision::Owner, nv_index_handle)
                .expect("call to nv_undefine_space failed");

            nv_read_result
        })
        .expect("call to nv_read failed");

    // Decryt the data using the key
    let cipher = ChaCha20Poly1305::new(read_data.as_bytes().into());
    cipher
        .decrypt(
            &encrypted_bundle.nonce,
            encrypted_bundle.encrypted_data.as_ref(),
        )
        .expect("could not decipher chacha20poly1305 encrypted data")
}

// Set up a non volatile storage space in the TPM for storing data
fn set_up_nv_space(context: &mut Context) -> NvIndexHandle {
    let nv_index = NvIndexTpmHandle::new(0x01500022).expect("failed to create NV index tpm handle");

    // Create NV index attributes
    let owner_nv_index_attributes = NvIndexAttributes::builder()
        .with_policy_write(true)
        .with_owner_write(true)
        .with_owner_read(true)
        .build()
        .expect("failed to create owner nv index attributes");

    let password_auth = Auth::try_from("mypassword".as_bytes().to_vec())
        .expect("failed to create authentication value");

    // Create owner nv public.
    let owner_nv_public = NvPublic::builder()
        .with_nv_index(nv_index)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(owner_nv_index_attributes)
        .with_data_area_size(256)
        .build()
        .expect("failed to build NvPublic for owner");

    // Define the NV space.
    let nv_index_handle = context
        .nv_define_space(Provision::Owner, Some(password_auth), owner_nv_public)
        .expect("call to nv_define_space failed");
    nv_index_handle
}
