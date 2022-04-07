use crate::aws;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
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
    /// The name of the folder in S3 where the encrypted files are stored
    pub s3_folder_name: Option<String>,
    pub encryption_dir: String,
}

impl KeyStore {
    pub fn new(filepath: String, encryption_dir: String) -> Self {
        return KeyStore {
            filepath,
            encryption_dir,
            encryption_key: Uuid::new_v4().to_string()[..32].to_string(),
            nonce: HashMap::new(),
            s3_folder_name: None
        };
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
            Ok(_) => println!("Keystore saved to: {path}"),
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

pub async fn decrypt_to_file(keystore_path: &str, output_file: &Option<String>) {
    let keystore = KeyStore::from_file(keystore_path);
    let cipher_key = Key::from_slice(keystore.encryption_key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let mut chunks: Vec<u8> = Vec::new();

    let filenames = keystore
        .nonce
        .keys()
        .sorted_by(|a, b| alphanumeric_sort::compare_str(a, b));

    for filename in filenames {
        println!("Decrypting {}", filename);
        let nonce_key = keystore.nonce.get(filename).unwrap();
        let mut file = File::open(&filename).expect(&format!("Couldn't open {filename}"));
        let mut buffer = Vec::new();

        file.read_to_end(&mut buffer)
            .expect(&format!("Couldn't read {filename}"));

        let mut decrypted_buffer = decrypt(&buffer, &cipher, &nonce_key);

        chunks.append(&mut decrypted_buffer);
    }

    let filepath = output_file.as_ref().unwrap_or(&keystore.filepath);

    let mut file = match File::create(&filepath) {
        Ok(value) => value,
        Err(why) => panic!("Failed to create output file {why}"),
    };

    match file.write_all(&chunks) {
        Ok(()) => println!("Output saved to {filepath}"),
        Err(why) => panic!("Error saving encrypted file: {why}"),
    }
}

pub async fn decrypt_from_bucket(keystore_path: &str, output_file: &Option<String>) {
    let keystore = KeyStore::from_file(keystore_path);
    let cipher_key = Key::from_slice(keystore.encryption_key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let mut chunks: Vec<u8> = Vec::new();

    let filenames = keystore
        .nonce
        .keys()
        .sorted_by(|a, b| alphanumeric_sort::compare_str(a, b));

    for filename in filenames {
        println!("Decrypting {}", filename);
        let nonce_key = keystore.nonce.get(&String::from(filename.clone())).unwrap();
        let content = aws::read_from_bucket(&String::from(filename.clone())).await;
        let mut decrypted_buffer = decrypt(&content, &cipher, &nonce_key);

        chunks.append(&mut decrypted_buffer);
    }

    let filepath = output_file.as_ref().unwrap_or(&keystore.filepath);

    let mut file = match File::create(&filepath) {
        Ok(value) => value,
        Err(why) => panic!("Failed to create output file {why}"),
    };

    match file.write_all(&chunks) {
        Ok(()) => println!("Output saved to {filepath}"),
        Err(why) => panic!("Error saving encrypted file: {why}"),
    }
}
