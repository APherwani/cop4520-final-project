#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_variables)]
#![allow(unused_imports)]

use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

const CHUNK_SIZE: usize = 5;

fn main() {
    // // Create a path to the desired file
    // let path = Path::new("../very_large_file.txt");
    // let display = path.display();

    // // Open the path in read-only mode, returns `io::Result<File>`
    // let mut file = match File::open(&path) {
    //     Err(why) => panic!("couldn't open {}: {}", display, why),
    //     Ok(file) => file,
    // };

    // // Read the file contents into a string, returns `io::Result<usize>`
    // let mut s = String::new();
    // match file.read_to_string(&mut s) {
    //     Err(why) => panic!("couldn't read {}: {}", display, why),
    //     Ok(_) => println!("Read new file containing {} characters.", s.len()),
    // }

    // Must be 32 bytes
    let encryption_key = "2c26481d-4c16-4985-a5bb-d7120eb2";
    // Must be 12 bytes
    let nonce_key = "4428fa183b99";

    let message = "Apparently motionless to her passengers and crew
    the Interplanetary liner Hyperion bored serenely onward through
    space at normal acceleration. In the railed-off sanctum in one
    corner of the control room a bell tinkled, a smothered whirr was
    heard, and Captain Bradley frowned as he studied the brief message
    upon the tape of the recorder--a message flashed to his desk
    from the operator's panel.";

    let cipher_key = Key::from_slice(encryption_key.as_bytes());
    let cipher = ChaCha20Poly1305::new(cipher_key);
    let nonce = Nonce::from_slice(nonce_key.as_bytes());

    encrypt_file("../encrypted.bin", &message, &cipher, &nonce);
    decrypt_file("../encrypted.bin", &cipher, &nonce);
}

fn split_file(s: &String) {
    for i in (0..100).step_by(CHUNK_SIZE) {
        println!(
            "s[{}..{}] = \n**{}**",
            i,
            i + CHUNK_SIZE,
            &s[i..(i + CHUNK_SIZE)]
        );
    }
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

fn decrypt_file(filename: &str, cipher: &ChaCha20Poly1305, nonce: &Nonce) {
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
        Ok(value) => String::from_utf8(value).expect("Couldn't decrypt text from file"),
        Err(why) => panic!("Failed to decrypt text: {}", why),
    };

    println!("Decrypted text: {}", plaintext);
}
