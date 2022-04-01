extern crate dotenv;

mod crypto;
mod aws;

use chacha20poly1305::aead::{NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key,};
use crypto::KeyStore;
use dotenv::dotenv;
use itertools::Itertools;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use uuid::Uuid;

const CHUNK_SIZE: usize = 250;
const ENCRYPTION_DIR: &str = "./encrypted";

#[tokio::main]
async fn main() {
    dotenv().expect("Failed to load .env");

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

    let mut keystore = KeyStore::new(path.display().to_string());

    let cipher_key = Key::from_slice(keystore.encryption_key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let chunks = split_text(&s, CHUNK_SIZE);

    // Remove the old encryption directory before the new one is created so we
    // don't end up with a bunch of old encrypted files but a new encryption key
    std::fs::remove_dir_all(ENCRYPTION_DIR).ok();
    std::fs::create_dir_all(ENCRYPTION_DIR).expect("Failed to create encryption directory");

    for (index, chunk) in chunks.iter().enumerate() {
        let nonce_key = Uuid::new_v4().to_string()[24..].to_string();
        let filename = format!(
            "{ENCRYPTION_DIR}/{index}_{}.bin",
            Uuid::new_v4().to_string()
        );

        let bytes = crypto::encrypt(&chunk, &cipher, nonce_key.as_ref());

        write_to_file(&filename, bytes);

        keystore.nonce.insert(filename, nonce_key);
    }

    keystore.write_to_file(&format!("{ENCRYPTION_DIR}/keystore.json"));
}

fn split_text(s: &String, chunk_size: usize) -> Vec<String> {
    return s
        .chars()
        .chunks(chunk_size)
        .into_iter()
        .map(|chunk| chunk.collect::<String>())
        .collect::<Vec<String>>();
}

fn write_to_file(filename: &str, bytes: Vec<u8>) {
    let mut file = File::create(filename).expect(&format!("Failed to open file: {filename}"));

    match file.write(&bytes) {
        Ok(bytes) => println!("{filename} saved => {bytes} bytes"),
        Err(why) => println!("Error saving encrypted file: {why}"),
    }
}

#[test]
fn test_encrypt_and_depcry() {
    let test_string = "The fox jumped over the fence.";

    let mut keystore = KeyStore::new(String::from("file.test"));

    let cipher_key = Key::from_slice(keystore.encryption_key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);

    let nonce_key = Uuid::new_v4().to_string()[24..].to_string();

    let bytes = crypto::encrypt(&test_string, &cipher, nonce_key.as_ref());

    let decrypted_string = crypto::decrypt(&bytes, &cipher, nonce_key.as_ref());

    assert_eq!(test_string, decrypted_string);
}