use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use uuid::Uuid;

/// Contains the main encryption key used for the `ChaCha20Poly1305` cipher
/// along with a map of nonce keys used to encrypt file chunks.
#[derive(Deserialize, Serialize, Debug)]
struct KeyStore {
    /// This is the master encryption key used for the cipher. It must be 32 bytes.
    encryption_key: String,
    /// In this hashmap, the key refers to the name of the encrypted file
    /// and the value refers to the nonce key used to encrypt the file.
    /// All must be 24 bytes.
    nonce: HashMap<String, String>,
}

const CHUNK_SIZE: usize = 500;
const ENCRYPTION_DIR: &str = "./encrypted";

fn main() {
    // Create a path to the desired file
    let path = Path::new("./medium_sized_file.txt");
    let display = path.display();

    // Open the path in read-only mode, returns `io::Result<File>`
    let mut file = match File::open(&path) {
        Err(why) => panic!("couldn't open {}: {}", display, why),
        Ok(file) => file,
    };

    // Read the file contents into a string, returns `io::Result<usize>`
    let mut s = String::new();
    match file.read_to_string(&mut s) {
        Err(why) => panic!("couldn't read {}: {}", display, why),
        Ok(_) => println!("Read new file containing {} characters.", s.len()),
    }

    let mut keystore = KeyStore {
        encryption_key: Uuid::new_v4().to_string()[..32].to_string(),
        nonce: HashMap::new(),
    };

    let cipher_key = Key::from_slice(keystore.encryption_key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let chunks = split_text(&s);

    match std::fs::create_dir_all(ENCRYPTION_DIR) {
        Ok(_) => (),
        Err(why) => panic!("Failed to created directory: {why}"),
    }

    for (index, chunk) in chunks.iter().enumerate() {
        let filename = format!("{ENCRYPTION_DIR}/{index}_{}.bin", Uuid::new_v4().to_string());
        let nonce_key = Uuid::new_v4().to_string()[24..].to_string();

        encrypt_file(
            &filename,
            &chunk,
            &cipher,
            nonce_key.as_ref(),
        );

        keystore.nonce.insert(filename, nonce_key);
    }

    let key_json =
        serde_json::to_string_pretty(&keystore).expect("Failed to serialize encryption keys.");
    let path = format!("{ENCRYPTION_DIR}/keystore.json");
    let keystore_path = Path::new(&path);
    
    let mut keystore_file = match File::create(keystore_path) {
        Ok(file) => file,
        Err(why) => panic!("Failed to keystore {}: {why}", keystore_path.display())
    };

    match keystore_file.write_all(&key_json.to_string().as_bytes()) {
        Ok(_) => println!("Key file saved to: {}", keystore_path.display()),
        Err(why) => println!("Error saving {}: {why}", keystore_path.display()),
    }
}

fn split_text(s: &String) -> Vec<String> {
    return s
        .chars()
        .chunks(CHUNK_SIZE)
        .into_iter()
        .map(|chunk| chunk.collect::<String>())
        .collect::<Vec<String>>();
}

fn encrypt_file(filename: &str, plaintext: &str, cipher: &ChaCha20Poly1305, nonce_key: &str) {
    let nonce = Nonce::from_slice(nonce_key.as_bytes());
    let ciphertext = match cipher.encrypt(nonce, plaintext.as_ref()) {
        Ok(value) => value,
        Err(why) => panic!("Failed to encrypt text: {why}"),
    };

    let mut file = File::create(filename).expect(&format!("Failed to open file: {filename}"));

    match file.write(&ciphertext) {
        Ok(n) => println!("{filename} saved => {n} bytes"),
        Err(why) => println!("Error saving encrypted file: {why}"),
    }
}

#[allow(unused)]
fn decrypt_file(filename: &str, cipher: &ChaCha20Poly1305, nonce_key: &str) -> String {
    let path = Path::new(filename);
    let display = path.display();
    let mut file = match File::open(&path) {
        Err(why) => panic!("Couldn't open file {display}: {why}"),
        Ok(file) => file,
    };

    let mut buffer: Vec<u8> = Vec::new();

    match file.read_to_end(&mut buffer) {
        Err(why) => panic!("Couldn't read {display}: {why}"),
        Ok(_) => (),
    }

    let nonce = Nonce::from_slice(nonce_key.as_bytes());
    let plaintext = match cipher.decrypt(nonce, buffer.as_ref()) {
        Ok(value) => {
            String::from_utf8(value).expect(&format!("Couldn't decrypt text from file: {filename}"))
        }
        Err(why) => panic!("Failed to decrypt text: {why}"),
    };

    return plaintext;
}
