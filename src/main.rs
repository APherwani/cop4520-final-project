extern crate dotenv;

mod aws;
mod cli_args;
mod crypto;

use chacha20poly1305::aead::NewAead;
use chacha20poly1305::{ChaCha20Poly1305, Key};
use clap::Parser;
use cli_args::{CLIArgs, Commands, EncryptCommand};
use crypto::KeyStore;
use dotenv::dotenv;
use itertools::Itertools;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use uuid::Uuid;

#[tokio::main]
async fn main() {
    dotenv().expect("Failed to load .env");

    let args = CLIArgs::parse();

    match &args.command {
        Commands::Encrypt(command) => encrypt(&command),
        Commands::Decrypt(command) => {
            crypto::decrypt_to_file(&command.keystore_path, &command.output_file)
        }
    }
}

fn read_file(file_path: &String) -> String {
    // Create a path to the desired file
    let path = Path::new(file_path);
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

    return s;
}

fn encrypt(args: &EncryptCommand) {
    let EncryptCommand {
        file_path,
        chunk_size,
        output_dir,
    } = args;

    
    let file_content = read_file(&file_path);
    let mut keystore = KeyStore::new(file_path.to_string());

    let cipher_key = Key::from_slice(keystore.encryption_key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let chunks = split_text(&file_content, *chunk_size);

    match output_dir {
        Some(path) => std::fs::create_dir_all(path).expect("Failed to create output directory"),
        None => ()
    }

    for (index, chunk) in chunks.iter().enumerate() {
        let nonce_key = Uuid::new_v4().to_string()[24..].to_string();
        let filename = output_dir.join(format!("{index}_{}.bin", Uuid::new_v4().to_string()));
        let bytes = crypto::encrypt(&chunk, &cipher, nonce_key.as_ref());

        write_to_file(&filename.display().to_string(), bytes);

        keystore
            .nonce
            .insert(filename.display().to_string(), nonce_key);
    }

    keystore.write_to_file(&output_dir.join("keystore.json").display().to_string());
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
fn test_encrypt_and_decrypt() {
    let test_string = "The fox jumped over the fence.";

    let keystore = KeyStore::new(String::from("file.test"));

    let cipher_key = Key::from_slice(keystore.encryption_key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);

    let nonce_key = Uuid::new_v4().to_string()[24..].to_string();

    let bytes = crypto::encrypt(&test_string, &cipher, nonce_key.as_ref());

    let decrypted_string = crypto::decrypt(&bytes, &cipher, nonce_key.as_ref());

    assert_eq!(test_string, decrypted_string);
}
