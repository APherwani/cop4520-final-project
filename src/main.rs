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
use rayon::prelude::*;

#[tokio::main]
async fn main() {
    dotenv().expect("Failed to load .env");

    let args = CLIArgs::parse();

    match &args.command {
        Commands::Encrypt(command) => encrypt(&command).await,
        Commands::Decrypt(command) => {
            crypto::decrypt_to_file(&command.keystore_path, &command.output_file).await
            // crypto::decrypt_from_bucket(&command.keystore_path, &command.output_file).await
        }
        Commands::Clear(command) => {
            aws::clear_directory(&command.dir_name).await
        }
        Commands::List(command) => {
            let items = aws::list_objects(&command.dir_name).await;
            for item in items {
                println!("{}", item)
            }
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

 async fn encrypt(args: &EncryptCommand) {
    let EncryptCommand {
        file_path,
        chunk_size,
        output_dir,
    } = args;

    let file_content = read_file(&file_path);
    let keystore = KeyStore::new(file_path.to_string());

    let cipher_key = Key::from_slice(keystore.encryption_key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let mut chunks = split_text(&file_content, *chunk_size);

    match output_dir {
        Some(dir) => std::fs::create_dir_all(dir).expect("Failed to create output directory"),
        None => (),
    }

    // 0_something something something

    // // If the output directory is passed, we'll save the chunks to the user's own
    // // computer, otherwise, we'll upload it to the AWS S3 bucket
    // for (index, chunk) in chunks.iter().enumerate() {
    //     let nonce_key = Uuid::new_v4().to_string()[24..].to_string();
    //     let bytes = crypto::encrypt(&chunk, &cipher, nonce_key.as_ref());

    //     let filename = match output_dir {
    //         Some(dir) => format!("{dir}/{index}_{}.bin", Uuid::new_v4().to_string()),
    //         None => format!("encrypted/{index}_{}.bin", Uuid::new_v4().to_string()),
    //     };

    //     match output_dir {
    //         Some(_) => write_to_file(&filename, bytes),
    //         None => {
    //             aws::write_to_bucket(&filename, bytes).await;
    //         }
    //     }

    //     keystore.nonce.insert(filename, nonce_key);
    // }

    // arr.par_iter_mut().for_each(|p| *p -= 1);
    chunks.par_iter_mut().enumerate().for_each(|(index, chunk)| {
        let nonce_key = Uuid::new_v4().to_string()[24..].to_string();
        let bytes = crypto::encrypt(&chunk, &cipher, nonce_key.as_ref());

        let filename = match output_dir {
            Some(dir) => format!("{dir}/{index}_{}.bin", Uuid::new_v4().to_string()),
            None => format!("encrypted/{}.bin", Uuid::new_v4().to_string()),
        };

        match output_dir {
            Some(_) => write_to_file(&filename, bytes),
            None => {
                // aws::write_to_bucket(&filename, bytes).await;
            }
        }

        // keystore.nonce.insert(filename, nonce_key);
        println!("\"{}\": {:?}", filename, nonce_key);
    });

    match output_dir {
        Some(dir) => keystore.write_to_file(&format!("{dir}/keystore.json")),
        None => keystore.write_to_file("keystore.json"),
    }
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
        Ok(bytes) => {},
        Err(why) => {}
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
