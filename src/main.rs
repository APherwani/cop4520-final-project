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
use rayon::prelude::*;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use tokio_stream::StreamExt;
use uuid::Uuid;

#[tokio::main]
async fn main() {
    dotenv().expect("Failed to load .env");

    let args = CLIArgs::parse();

    match &args.command {
        Commands::Encrypt(command) => encrypt(&command).await,
        Commands::Decrypt(command) => crypto::decrypt_to_file(&command).await,
        Commands::Clear(command) => aws::clear_directory(&command.dir_name).await,
        Commands::List(command) => {
            let items = aws::list_objects(&command.dir_name).await;
            items.iter().for_each(|item| println!("{item}"));
        }
    }
}

fn read_file(file_path: &String) -> Vec<u8> {
    // Create a path to the desired file
    let path = Path::new(file_path);
    let display = path.display();

    // Open the path in read-only mode, returns `io::Result<File>`
    let mut file = match File::open(&path) {
        Err(why) => panic!("couldn't open {}: {}", display, why),
        Ok(file) => file,
    };

    // Read the file contents into a vector, returns `io::Result<usize>`
    let mut buffer = Vec::new();

    file.read_to_end(&mut buffer)
        .expect(&format!("Couldn't read {display}"));

    return buffer;
}

async fn encrypt(args: &EncryptCommand) {
    let EncryptCommand {
        file_path,
        chunk_size,
        output_dir,
        use_aws,
    } = args;

    let output_dir = match output_dir {
        Some(dir) => dir.clone(),
        None => Uuid::new_v4().to_string(),
    };

    let mut keystore = KeyStore::new(file_path.to_string(), output_dir.to_string());
    let cipher_key = Key::from_slice(keystore.encryption_key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let file_content = read_file(&file_path);
    let chunks = file_content.par_chunks(*chunk_size);

    if !*use_aws {
        match std::fs::create_dir(&output_dir) {
            Ok(()) => (),
            Err(why) => panic!("Failed to create {output_dir}: {why}"),
        }
    }

    let something = chunks
        .into_par_iter()
        .enumerate()
        .map(|(index, chunk)| {
            let nonce_key = Uuid::new_v4().to_string()[24..].to_string();
            let bytes = crypto::encrypt(&chunk, &cipher, nonce_key.as_ref());
            let filename = format!("{output_dir}/{index}_{}.bin", Uuid::new_v4().to_string());

            if !*use_aws {
                write_to_file(&filename, &bytes);
            }

            return (nonce_key, filename, bytes);
        })
        .collect::<Vec<_>>();

    for (nonce_key, filename, _) in &something {
        keystore.nonce.insert(filename.clone(), nonce_key.clone());
    }

    if *use_aws {
        let mut stream = tokio_stream::iter(something);

        while let Some((_, filename, bytes)) = stream.next().await {
            aws::write_to_bucket(&filename, bytes).await;
        }
    }

    keystore.write_to_file(&format!("keystore-{output_dir}.json"));
}

fn write_to_file(filename: &str, bytes: &Vec<u8>) {
    let mut file = File::create(filename).expect(&format!("Failed to open file: {filename}"));

    match file.write(bytes) {
        Ok(bytes) => {}
        Err(why) => {}
    }
}

// TODO: Fix this somehow
// #[test]
// fn test_encrypt_and_decrypt() {
//     let test_string = "The fox jumped over the fence.";

//     let keystore = KeyStore::new(String::from("file.test"));

//     let cipher_key = Key::from_slice(keystore.encryption_key.as_bytes());
//     let cipher = ChaCha20Poly1305::new(cipher_key);

//     let nonce_key = Uuid::new_v4().to_string()[24..].to_string();

//     let bytes = crypto::encrypt(&test_string, &cipher, nonce_key.as_ref());

//     let decrypted_string = crypto::decrypt(&bytes, &cipher, nonce_key.as_ref());

//     assert_eq!(test_string, decrypted_string);
// }
