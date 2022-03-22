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
    /// The path of the original unencrypted file.
    filepath: String,
    /// This is the master encryption key used for the cipher. It **must** be 32 bytes.
    encryption_key: String,
    /// In this hashmap, the key refers to the name of the encrypted file
    /// and the value refers to the nonce key used to encrypt the file.
    /// All nonce keys **must** be 24 bytes.
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
        filepath: path.display().to_string(),
        encryption_key: Uuid::new_v4().to_string()[..32].to_string(),
        nonce: HashMap::new(),
    };

    let cipher_key = Key::from_slice(keystore.encryption_key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let chunks = split_text(&s, CHUNK_SIZE);

    // Remove the old encryption directory before the new one is created so we
    // don't end up with a bunch of old encrypted files but a new encryption key
    std::fs::remove_dir_all(ENCRYPTION_DIR).expect("Failed to remove encryption directory");
    std::fs::create_dir_all(ENCRYPTION_DIR).expect("Failed to create encryption directory");

    for (index, chunk) in chunks.iter().enumerate() {
        let nonce_key = Uuid::new_v4().to_string()[24..].to_string();
        let filename = format!(
            "{ENCRYPTION_DIR}/{index}_{}.bin",
            Uuid::new_v4().to_string()
        );

        encrypt_file(&filename, &chunk, &cipher, nonce_key.as_ref());

        keystore.nonce.insert(filename, nonce_key);
    }

    let key_json = serde_json::to_string_pretty(&keystore).expect("Failed to serialize keystore.");
    let path = format!("{ENCRYPTION_DIR}/keystore.json");
    let keystore_path = Path::new(&path);
    let mut keystore_file = File::create(keystore_path).expect("Failed to create keystore file");

    match keystore_file.write_all(&key_json.to_string().as_bytes()) {
        Ok(_) => println!("Keystore saved to: {}", keystore_path.display()),
        Err(why) => println!("Error saving {}: {why}", keystore_path.display()),
    }
}

fn split_text(s: &String, chunk_size: usize) -> Vec<String> {
    return s.chars()
        .chunks(chunk_size)
        .into_iter()
        .map(|chunk| chunk.collect::<String>())
        .collect::<Vec<String>>();
}

fn encrypt_file(filename: &str, plaintext: &str, cipher: &ChaCha20Poly1305, nonce_key: &str) {
    let nonce = Nonce::from_slice(nonce_key.as_bytes());
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .expect("Failed to encrypt text");

    let mut file = File::create(filename).expect(&format!("Failed to open file: {filename}"));

    match file.write(&ciphertext) {
        Ok(bytes) => println!("{filename} saved => {bytes} bytes"),
        Err(why) => println!("Error saving encrypted file: {why}"),
    }
}

#[allow(unused)]
fn decrypt_file(filename: &str, cipher: &ChaCha20Poly1305, nonce_key: &str) -> String {
    let path = Path::new(filename);
    let display = path.display();
    let mut file = File::open(&path).expect(&format!("Couldn't open {display}"));
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer)
        .expect(&format!("Couldn't read {display}"));

    let nonce = Nonce::from_slice(nonce_key.as_bytes());
    let plaintext = match cipher.decrypt(nonce, buffer.as_ref()) {
        Ok(value) => {
            String::from_utf8(value).expect(&format!("Couldn't decrypt text from file: {filename}"))
        }
        Err(why) => panic!("Failed to decrypt text: {why}"),
    };

    return plaintext;
}

/// For debug purposes. Decrypts all files in `ENCRYPTION_DIR` and
/// prints the resulting content.
#[allow(unused)]
fn decrypt_directory() {
    let mut json_string = String::new();
    let mut keystore_file =
        File::open(format!("{ENCRYPTION_DIR}/keystore.json")).expect("Couldn't open keystore file");

    keystore_file
        .read_to_string(&mut json_string)
        .expect("Failed to read keystore file");

    let keystore: KeyStore =
        serde_json::from_str(&json_string).expect("Couldn't parse keystore JSON file");

    let cipher_key = Key::from_slice(keystore.encryption_key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);

    println!("\n\n[{}]\n\n", keystore.filepath);

    // TODO: This doesn't sort in the order we want it to. It should be:
    // 0_chunk, 1_chunk, 2_chunk, 3_chunk, ..., n_chunk, but instead it's:
    // 0_chunk, 1_chunk, 11_chunk, 12_chunk, ..., 20_chunk, 21_chunk, ...
    for filename in keystore.nonce.keys().sorted() {
        let nonce_key = keystore.nonce.get(filename).unwrap();
        let plaintext = decrypt_file(&filename, &cipher, &nonce_key);
        print!("{plaintext}");
    }

    println!();
}
