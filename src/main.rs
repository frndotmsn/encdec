use std::io::{read_to_string, Write};

use aead::consts::U12;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key // Or `Aes128Gcm`
};

use base64::{Engine as _, engine::general_purpose};

fn encrypt(key: &Key<Aes256Gcm>, nonce: &Nonce<U12>, plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(&key);
    cipher.encrypt(&nonce, plaintext).unwrap()
}

fn decrypt(key: &Key<Aes256Gcm>, nonce: &Nonce<U12>, ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(&key);
    cipher.decrypt(&nonce, ciphertext).unwrap()
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();

    // if no args are provided tell user that mode and filein and fileout are required
    if args.len() < 5 {
        println!("Usage: {} <mode> <filepath_in> <filepath_out> <key>", args[0]);
        return;
    }

    // get mode and filepath from args
    let mode = args[1].as_str();
    let filepath_in = args[2].as_str();
    let filepath_out = args[3].as_str();
    let key_str = args[4].as_str();
    if key_str.len() > 32 {
        println!("Key must be max 32 characters long");
        return;
    }
    // pad key with 0s to 32 bytes
    let mut key_bytes = [0; 32];
    for (i, c) in key_str.chars().enumerate() {
        key_bytes[i] = c as u8;
    }
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

    match mode {
        "encrypt" => {
            let filein = std::fs::File::open(filepath_in).unwrap();
            let mut fileout = std::fs::File::create(filepath_out).unwrap();

            println!("Encrypting file: {}", filepath_in);
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let contents = read_to_string(filein).unwrap();
            let encrypted = general_purpose::STANDARD_NO_PAD.encode(&encrypt(key, &nonce, contents.as_bytes()));
            let nonce_appendix = format!("\r\n\r\nNonce: {}", general_purpose::STANDARD_NO_PAD.encode(&nonce));
            // create a new string with the encrypted contents and the nonce appendix efficiently using Vec<u8> and extend
            let mut buf = Vec::with_capacity(encrypted.len() + nonce_appendix.len());
            buf.extend(encrypted.as_bytes());
            buf.extend(nonce_appendix.as_bytes());
            fileout.write_all(&buf).unwrap();
        },
        "decrypt" => {
            let filein: std::fs::File = std::fs::File::open(filepath_in).unwrap();
            let mut fileout = std::fs::File::create(filepath_out).unwrap();

            println!("Decrypting file: {}", filepath_in);

            // seperate the nonce and the encrypted contents using one read_to_string call and split
            let contents = read_to_string(filein).unwrap();
            let mut contents_iter = contents.split("\r\n\r\nNonce: ");
            let encrypted = contents_iter.next().unwrap().as_bytes();
            let nonce_bytes = general_purpose::STANDARD_NO_PAD.decode(contents_iter.next().unwrap().as_bytes()).unwrap();
            let nonce_bytes: &[u8; 12] = nonce_bytes.as_slice().try_into().unwrap();
            let nonce = Nonce::<U12>::from_slice(nonce_bytes);
                        // decrypt the contents
            let decrypted = decrypt(key, nonce, &general_purpose::STANDARD_NO_PAD.decode(encrypted).unwrap());
            fileout.write_all(&decrypted).unwrap();
        },
        _ => {
            println!("Invalid mode: {}", mode);
            return;
        }
    }
}
