use crate::aws;
use crate::cli_args::DecryptCommand;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use uuid::Uuid;

/// Contains the main encryption key used for the `ChaCha20Poly1305` cipher
/// along with a map of nonce keys used to encrypt file chunks.
#[derive(Deserialize, Serialize, Debug)]
pub struct KeyStore {
    /// The path of the original unencrypted file.
    pub filepath: String,
    /// This is the master encryption key used for the cipher. It **must** be 32 bytes.
    pub encryption_key: String,
    /// In this hashmap, the key refers to the name of the encrypted file
    /// and the value refers to the nonce key used to encrypt the file.
    /// All nonce keys **must** be 24 bytes.
    pub nonce: HashMap<String, String>,
    /// The name of the directory where the encrypted files are stored
    pub encryption_dir: String,
}

impl KeyStore {
    pub fn new(filepath: String, encryption_dir: String) -> Self {
        KeyStore {
            filepath,
            encryption_dir,
            encryption_key: Uuid::new_v4().to_string()[..32].to_string(),
            nonce: HashMap::new(),
        }
    }

    /// Takes a path to a keystore JSON file and creates a KeyStore
    /// object from its content
    pub fn from_file(path: &str) -> Self {
        let mut json_string = String::new();
        let mut keystore_file = File::open(path).expect("Couldn't open keystore file");

        keystore_file
            .read_to_string(&mut json_string)
            .expect("Failed to read keystore file");

        return serde_json::from_str(&json_string).expect("Couldn't parse keystore JSON file");
    }

    pub fn write_to_file(&self, path: &str) {
        let key_json = serde_json::to_string_pretty(&self).expect("Failed to serialize keystore.");
        let mut keystore_file = File::create(path).expect("Failed to create keystore file");

        match keystore_file.write_all(&key_json.to_string().as_bytes()) {
            Ok(_) => println!("Keystore saved to {path}"),
            Err(why) => println!("Error saving {path}: {why}"),
        }
    }
}

pub fn encrypt(bytes: &[u8], cipher: &ChaCha20Poly1305, nonce_key: &str) -> Vec<u8> {
    let nonce = Nonce::from_slice(nonce_key.as_bytes());
    let buffer = cipher
        .encrypt(nonce, bytes.as_ref())
        .expect("Failed to encrypt buffer");

    return buffer;
}

pub fn decrypt(bytes: &Vec<u8>, cipher: &ChaCha20Poly1305, nonce_key: &str) -> Vec<u8> {
    let nonce = Nonce::from_slice(nonce_key.as_bytes());
    let buffer = match cipher.decrypt(nonce, bytes.as_ref()) {
        Ok(value) => value,
        Err(why) => panic!("Failed to decrypt buffer: {why}"),
    };

    return buffer;
}

pub async fn decrypt_to_file(args: &DecryptCommand) {
    let DecryptCommand {
        keystore_path,
        output_file,
        delete_dir,
        use_aws,
    } = args;

    let keystore = KeyStore::from_file(keystore_path);
    let cipher_key = Key::from_slice(keystore.encryption_key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let mut chunks: Vec<u8> = Vec::new();

    let filenames = keystore
        .nonce
        .keys()
        .sorted_by(|a, b| alphanumeric_sort::compare_str(a, b));

    let filepath = output_file.as_ref().unwrap_or(&keystore.filepath);

    // Create the file for writing. If the file already exists, this
    // will throw an error
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(filepath)
    {
        Ok(value) => value,
        Err(why) => panic!("Failed to create {filepath}: {why}"),
    };

    for filename in filenames {
        println!("Decrypting {}", filename);
        let nonce_key = keystore.nonce.get(filename).unwrap();

        // If we're decrypting from the S3 bucket, we'll read the contents of the file
        // from the bucket into a u8 vector, otherwise, we'll read contents of
        // the file on the user's local system into a u8 vector
        let encrypted_content = if *use_aws {
            aws::read_from_bucket(&String::from(filename.clone())).await
        } else {
            let mut file = File::open(&filename).expect(&format!("Couldn't open {filename}"));
            let mut buffer = Vec::new();

            file.read_to_end(&mut buffer)
                .expect(&format!("Couldn't read {filename}"));

            buffer
        };

        let mut decrypted_buffer = decrypt(&encrypted_content, &cipher, &nonce_key);
        chunks.append(&mut decrypted_buffer);
    }

    // If the --delete option was passed, we'll delete the keystore file
    // and remove the encrypted files from either the user's system or
    // the S3 bucket
    if *delete_dir {
        match std::fs::remove_file(&keystore_path) {
            Ok(()) => println!("Removed {}", &keystore_path),
            Err(why) => panic!("Failed to remove {}: {why}", &keystore.encryption_dir),
        }

        if *use_aws {
            println!("Removing AWS directory...");
            aws::clear_directory(&format!("{}/", &keystore.encryption_dir)).await;
        } else {
            match std::fs::remove_dir_all(&keystore.encryption_dir) {
                Ok(()) => (),
                Err(why) => panic!(
                    "Failed to remove directory {}: {why}",
                    &keystore.encryption_dir
                ),
            }
        }

        println!("Removed directory {}", &keystore.encryption_dir);
    }

    match file.write_all(&chunks) {
        Ok(()) => println!("Output saved to {filepath}"),
        Err(why) => panic!("Error saving encrypted file: {why}"),
    }
}
