#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use async_std::task;
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use itertools::Itertools;
use std::cmp;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

const CHUNK_SIZE: usize = 500;

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

    // Must be 32 bytes
    let encryption_key = "2c26481d-4c16-4985-a5bb-d7120eb2";
    // Must be 12 bytes
    let nonce_key = "4428fa183b99";

    let cipher_key = Key::from_slice(encryption_key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let nonce = Nonce::from_slice(nonce_key.as_bytes());

    let chunks = split_text(&s);

    match std::fs::create_dir_all("./encrypted") {
        Ok(_) => (),
        Err(why) => println!("Failed to created directory: {}", why),
    }

    for (index, chunk) in chunks.iter().enumerate() {
        let filename = format!("./encrypted/chunk-{}.bin", index);
        encrypt_file(&filename, &chunk, &cipher, &nonce);
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

fn encrypt_file(filename: &str, plaintext: &str, cipher: &ChaCha20Poly1305, nonce: &Nonce) {
    let ciphertext = match cipher.encrypt(nonce, plaintext.as_ref()) {
        Ok(value) => value,
        Err(why) => panic!("Failed to encrypt text: {}", why),
    };

    let mut file = File::create(filename).expect("Failed to open file");

    match file.write(&ciphertext) {
        Ok(n) => println!("{} saved => {} bytes", filename, n),
        Err(why) => println!("Error saving encrypted file: {}", why),
    }
}

fn decrypt_file(filename: &str, cipher: &ChaCha20Poly1305, nonce: &Nonce) -> String {
    let path = Path::new(filename);
    let display = path.display();
    let mut file = match File::open(&path) {
        Err(why) => panic!("Couldn't open {}: {}", display, why),
        Ok(file) => file,
    };

    let mut buffer: Vec<u8> = Vec::new();

    match file.read_to_end(&mut buffer) {
        Err(why) => panic!("Couldn't read {}: {}", display, why),
        Ok(_) => (),
    }

    let plaintext = match cipher.decrypt(nonce, buffer.as_ref()) {
        Ok(value) => {
            let error_message = format!("Couldn't decrypt text from file: {}", filename);
            String::from_utf8(value).expect(&error_message)
        }
        Err(why) => panic!("Failed to decrypt text: {}", why),
    };

    return plaintext;
}
