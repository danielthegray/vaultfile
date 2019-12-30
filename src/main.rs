extern crate rsa;
extern crate rand;
extern crate base64;

use rand::RngCore;
use rsa::{PublicKey, RSAPublicKey, RSAPrivateKey, PaddingScheme};

use aes_soft::block_cipher_trait::generic_array::GenericArray;
use aes_soft::block_cipher_trait::BlockCipher;
use aes_soft::Aes256;

use std::fs::File;
use std::io::prelude::{Read, Write};
use std::path::Path;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct VaultfileSecret {
    secret: String,
    // the encryption key to the secret is stored
    // under the name of the key used to encrypt it
    encrypted_key: HashMap<String, String>,
}
#[derive(Serialize, Deserialize)]
struct Vaultfile {
    keys: HashMap<String, RSAPublicKey>,
    // each secret is stored under a name
    secrets: HashMap<String, VaultfileSecret>,
}

fn generate_new_key(private_key_path: &str) {
    let mut rng = rand::rngs::OsRng;
    let bits = 2048;
    let private_key = RSAPrivateKey::new(&mut rng, bits)
        .expect("Failed to generate key!");
    let private_key_json = serde_json::to_string(&private_key).unwrap();
    match write_json_to_file(private_key_path, private_key_json) {
        Ok(_) => (),
        Err(error) => panic!(error),
    }
}

fn load_private_key(private_key_path: &str) -> Result<RSAPrivateKey, String> {
    let private_key_json = load_json_from_file(private_key_path)?;
    match serde_json::from_str(&private_key_json) {
        Ok(private_key) => Ok(private_key),
        Err(error) => Err(format!("Error while parsing private key in file {}! Error: {:?}", private_key_path, error)),
    }
}

fn load_vaultfile(vaultfile_path: &str) -> Result<Vaultfile, String> {
    let vaultfile_json = load_json_from_file(vaultfile_path)?;
    match serde_json::from_str(&vaultfile_json) {
        Ok(vaultfile) => Ok(vaultfile),
        Err(error) => Err(format!("Error while parsing vaultfile at {}! Error: {:?}", vaultfile_path, error)),
    }
}

fn write(vaultfile_path: &str, secret_name: String, secret_value: String) -> Result<(), String> {
    let mut rng = rand::rngs::OsRng;
    let mut vaultfile = load_vaultfile(vaultfile_path)?;
    let mut encrypted_key: HashMap<String, String> = HashMap::new();
    let encrypted_secret = encrypt_string(secret_value);
    for (key_name, rsa_key) in vaultfile.keys.iter() {
        let aes_key_ciphertext = match rsa_key.encrypt(&mut rng, PaddingScheme::PKCS1v15, &encrypted_secret.aes_key) {
            Ok(ciphertext) => ciphertext,
            Err(error) => return Err(format!("Error while encrypting AES key: {:?}", error)),
        };
        let aes_key_ciphertext = base64::encode(&aes_key_ciphertext);
        encrypted_key.insert(String::from(key_name), aes_key_ciphertext);
    }
    // we simply update the value, without checking for a
    // collision, since this is the expected use case.
    // User confirmation will be implemented separately.
    vaultfile.secrets.insert(secret_name, VaultfileSecret {
        encrypted_key,
        secret: encrypted_secret.encrypted_base
    });
    let vaultfile_json = match serde_json::to_string_pretty(&vaultfile) {
        Ok(json) => json,
        Err(error) => return Err(format!("Error while converting to JSON: {:?}", error)),
    };
    write_json_to_file_without_checking(vaultfile_path, vaultfile_json)?;
    Ok(())
}

struct EncryptionResult {
    aes_key: [u8; 32],
    encrypted_base: String,
}

fn encrypt_string(plaintext: String) -> EncryptionResult {
    let mut key: [u8; 32] = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let key_for_aes = GenericArray::clone_from_slice(&key);
    let cipher = Aes256::new(&key_for_aes);
    let plaintext_bytes = (&plaintext).as_bytes();
    let mut plaintext_bytes = GenericArray::clone_from_slice(&plaintext_bytes);

    cipher.encrypt_block(&mut plaintext_bytes);
    let ciphertext_base64 = base64::encode(&plaintext_bytes);
    EncryptionResult {
        aes_key: key,
        encrypted_base: ciphertext_base64,
    }
}

fn write_json_to_file(json_file_path: &str, json: String) -> Result<(), String> {
    if Path::new(json_file_path).exists() {
        return Err(format!("JSON file {} already exists!", json_file_path));
    }
    write_json_to_file_without_checking(json_file_path, json)
}

fn write_json_to_file_without_checking(json_file_path: &str, json: String) -> Result<(), String> {
    let json_file = File::create(json_file_path);
    let mut json_file = match json_file {
        Ok(file) => file,
        Err(error) => return Err(format!("Couldn't write JSON file at path {}! Error: {:?}", json_file_path, error)),
    };
    match json_file.write_all(json.as_bytes()) {
        Ok(_) => (),
        Err(error) => return Err(format!("Error while writing JSON to file {}! Error: {:?}", json_file_path, error)),
    }
    Ok(())
}

fn load_json_from_file(json_file_path: &str) -> Result<String, String> {
    let json_file = File::open(json_file_path);
    let mut json_file = match json_file {
        Ok(file) => file, 
        Err(error) => return Err(format!("Error while opening file {}! Error: {:?}", json_file_path, error)),
    };
    let mut json_string = String::new();
    match json_file.read_to_string(&mut json_string) {
        Ok(_) => (),
        Err(error) => return Err(format!("Error while reading contents of file {}! Error: {:?}", json_file_path, error)),
    }
    Ok(json_string)
}

fn print_help() {
    println!("vaultfile - A basic shared secret manager");
    println!("
    Vaultfile is an encrypted secret store (like KeePassXC or other password
    managers) with several access keys, instead of a single master access key.
    
    The following options exist:
    
    --new-key[=NAME]     Generate a new key to be used with Vaultfile.
                         Optionally, a name can be provided
                         (by default it will be \"vault\").
    
    ");
}

fn main() {
    let cli_args = std::env::args();
    generate_new_key("test.key");
    if cli_args.len() < 2 {
        print_help();
    }
}
