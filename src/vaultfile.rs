extern crate base64;
extern crate crypto;
extern crate rsa;

use crypto::aessafe::{AesSafe256DecryptorX8, AesSafe256EncryptorX8};
use crypto::symmetriccipher::{BlockDecryptorX8, BlockEncryptorX8};
use rsa::rand_core::{RngCore, SeedableRng};
use rsa::{PaddingScheme, PublicKey, PublicKeyParts, RsaPrivateKey, RsaPublicKey};

use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::File;
use std::io::prelude::{Read, Write};
use std::iter::FromIterator;
use std::path::Path;

use serde::{Deserialize, Serialize};

const PADDING: PaddingScheme = PaddingScheme::PKCS1v15Encrypt;

#[derive(Serialize, Deserialize)]
pub struct VaultfileSecret {
    secret: String,
    // the encryption key to the secret is stored
    // under the name of the key used to encrypt it
    encrypted_key: HashMap<String, String>,
}

#[derive(Serialize, Deserialize)]
pub struct Vaultfile {
    keys: HashMap<String, RsaPublicKey>,
    // each secret is stored under a name
    secrets: HashMap<String, VaultfileSecret>,
}

impl Vaultfile {
    pub fn new() -> Vaultfile {
        Vaultfile {
            keys: HashMap::new(),
            secrets: HashMap::new(),
        }
    }

    pub fn load_from_file(vaultfile_path: &Path) -> Result<Vaultfile, VaultfileError> {
        if !vaultfile_path.is_file() {
            return Err(VaultfileError {
                kind: VaultfileErrorKind::VaultfileNotFound,
            });
        }
        let vaultfile_json = load_json_from_file(vaultfile_path)?;
        let vaultfile: Vaultfile = serde_json::from_str(&vaultfile_json)?;
        vaultfile.validate()?;
        Ok(vaultfile)
    }

    fn validate(&self) -> Result<(), VaultfileError> {
        if self.keys.len() == 0 {
            return Err(VaultfileError {
                kind: VaultfileErrorKind::VaultfileMustHaveKeys,
            });
        }
        // we ensure that all registered keys can access all of the secrets in the vaultfile
        for registered_key_name in self.keys.keys() {
            for (secret_name, secret) in self.secrets.iter() {
                let key_can_access_secret = secret
                    .encrypted_key
                    .keys()
                    .any(|key_name_in_secret| registered_key_name == key_name_in_secret);
                if !key_can_access_secret {
                    return Err(VaultfileError {
                        kind: VaultfileErrorKind::SecretNotSharedWithAllRegisteredKeys(
                            String::from(secret_name),
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    pub fn generate_key() -> RsaPrivateKey {
        let mut rng = rand_chacha::ChaChaRng::from_entropy();
        let bits = 2048;
        RsaPrivateKey::new(&mut rng, bits).expect("Failed to generate key!")
    }

    pub fn generate_and_save_key(private_key_path: &Path) -> Result<(), VaultfileError> {
        let public_key_path = format!("{}.pub", private_key_path.to_str().unwrap());
        let public_key_path = Path::new(&public_key_path);
        let private_key = Vaultfile::generate_key();
        let public_key = private_key.to_public_key();
        let private_key_json = serde_json::to_string(&private_key).unwrap();
        let public_key_json = serde_json::to_string(&public_key).unwrap();
        match write_json_to_file(private_key_path, private_key_json, true) {
            Ok(_) => (),
            Err(error) => panic!("{}", error),
        };
        match write_json_to_file(public_key_path, public_key_json, true) {
            Ok(_) => Ok(()),
            Err(error) => panic!("{}", error),
        }
    }

    pub fn find_registered_name_of_key<T: PublicKey>(&self, key: &T) -> Option<String> {
        for (key_name, registered_key) in self.keys.iter() {
            if registered_key.n() == key.n() && registered_key.e() == key.e() {
                return Some(String::from(key_name));
            }
        }
        return None;
    }

    pub fn is_key_registered(&self, key_name: &str) -> bool {
        self.keys.contains_key(key_name)
    }

    pub fn get_key(&self, key_name: &str) -> Option<RsaPublicKey> {
        match self.keys.get(key_name) {
            Some(pub_key) => {
                Some(RsaPublicKey::new(pub_key.n().clone(), pub_key.e().clone()).unwrap())
            }
            None => None,
        }
    }

    /// Registers a new key in the vaultfile, under a specified name.
    /// If a key under that name already exists, it will be overwritten.
    pub fn register_key(
        &mut self,
        name_new_key: &str,
        new_key: RsaPublicKey,
        already_registered_private_key: &RsaPrivateKey,
    ) -> Result<(), VaultfileError> {
        if self.secrets.len() > 0 {
            let private_key_name = match self
                .find_registered_name_of_key(&RsaPublicKey::from(already_registered_private_key))
            {
                Some(key_name) => key_name,
                None => {
                    return Err(VaultfileError {
                        kind: VaultfileErrorKind::PrivateKeyNotRegistered,
                    });
                }
            };
            let mut rng = rand_chacha::ChaChaRng::from_entropy();
            // we now grant access to all the shared secrets to the newly registered key
            for (secret_name, secret) in self.secrets.iter_mut() {
                let encrypted_key = match secret.encrypted_key.get(&private_key_name) {
                    Some(key) => key,
                    None => {
                        return Err(VaultfileError {
                            kind: VaultfileErrorKind::SecretNotSharedWithAllRegisteredKeys(
                                String::from(secret_name),
                            ),
                        })
                    }
                };
                let raw_encrypted_key = base64::decode(&encrypted_key)?;
                let raw_aes_key =
                    already_registered_private_key.decrypt(PADDING, &raw_encrypted_key)?;
                // we encrypt the AES key using the newly registered public key
                // to grant them access to the secret
                let new_encrypted = new_key.encrypt(&mut rng, PADDING, &raw_aes_key)?;
                let base64_encrypted_key = base64::encode(&new_encrypted);
                secret
                    .encrypted_key
                    .insert(String::from(name_new_key), base64_encrypted_key);
            }
        }
        self.keys.insert(String::from(name_new_key), new_key);
        Ok(())
    }

    pub fn deregister_key(&mut self, key_name: &str) -> Result<(), VaultfileError> {
        if self.keys.len() == 1 {
            return Err(VaultfileError {
                kind: VaultfileErrorKind::VaultfileMustHaveKeys,
            });
        }
        if !self.keys.contains_key(key_name) {
            return Err(VaultfileError {
                kind: VaultfileErrorKind::VaultfileKeyNotRegistered(String::from(key_name)),
            });
        }
        for (_secret_name, secret) in self.secrets.iter_mut() {
            secret.encrypted_key.remove(key_name);
        }
        self.keys.remove(key_name);
        Ok(())
    }

    pub fn list_keys(&self) -> Vec<String> {
        Vec::from_iter(self.keys.keys().map(|key_name| String::from(key_name)))
    }

    pub fn list_secrets(&self) -> Vec<String> {
        Vec::from_iter(self.secrets.keys().map(|key_name| String::from(key_name)))
    }

    pub fn has_secret_named(&self, secret_name: &str) -> bool {
        self.secrets.contains_key(secret_name)
    }

    pub fn add_secret_utf8(
        &mut self,
        secret_name: &str,
        secret_value_utf8: &str,
    ) -> Result<(), VaultfileError> {
        let mut rng = rand_chacha::ChaChaRng::from_entropy();
        let mut encrypted_key: HashMap<String, String> = HashMap::new();
        let encrypted_secret = encrypt_utf8_string(secret_value_utf8);
        for (key_name, rsa_key) in self.keys.iter() {
            let aes_key_ciphertext =
                rsa_key.encrypt(&mut rng, PADDING, &encrypted_secret.aes_key)?;
            let aes_key_ciphertext = base64::encode(&aes_key_ciphertext);
            encrypted_key.insert(String::from(key_name), aes_key_ciphertext);
        }
        // we simply update the value, without checking for a
        // collision, since this is the expected use case.
        // User confirmation will be implemented separately.
        self.secrets.insert(
            String::from(secret_name),
            VaultfileSecret {
                encrypted_key,
                secret: encrypted_secret.encrypted_base,
            },
        );
        Ok(())
    }

    pub fn add_secret_base64(
        &mut self,
        secret_name: &str,
        secret_value_base64: &str,
    ) -> Result<(), VaultfileError> {
        let mut rng = rand_chacha::ChaChaRng::from_entropy();
        let mut encrypted_key: HashMap<String, String> = HashMap::new();
        // TODO: add explicit error for when the base64 input string is bad!
        let encrypted_secret = encrypt_base64_string(secret_value_base64)?;
        for (key_name, rsa_key) in self.keys.iter() {
            let aes_key_ciphertext =
                rsa_key.encrypt(&mut rng, PADDING, &encrypted_secret.aes_key)?;
            let aes_key_ciphertext = base64::encode(&aes_key_ciphertext);
            encrypted_key.insert(String::from(key_name), aes_key_ciphertext);
        }
        // we simply update the value, without checking for a
        // collision, since this is the expected use case.
        // User confirmation will be implemented separately.
        self.secrets.insert(
            String::from(secret_name),
            VaultfileSecret {
                encrypted_key,
                secret: encrypted_secret.encrypted_base,
            },
        );
        Ok(())
    }

    pub fn read_secret(
        &self,
        secret_name: &str,
        private_key: &RsaPrivateKey,
    ) -> Result<String, VaultfileError> {
        let key_name = match self.find_registered_name_of_key(&RsaPublicKey::from(private_key)) {
            Some(name) => name,
            None => {
                return Err(VaultfileError {
                    kind: VaultfileErrorKind::PrivateKeyNotRegistered,
                })
            }
        };
        let secret_to_read = match self.secrets.get(secret_name) {
            Some(secret) => secret,
            None => {
                return Err(VaultfileError {
                    kind: VaultfileErrorKind::SecretNotFound(String::from(secret_name)),
                })
            }
        };
        let encrypted_secret = &secret_to_read.secret;
        let base64_aes_key = match secret_to_read.encrypted_key.get(&key_name) {
            Some(b64_key) => b64_key,
            None => {
                return Err(VaultfileError {
                    kind: VaultfileErrorKind::SecretNotSharedWithAllRegisteredKeys(String::from(
                        secret_name,
                    )),
                })
            }
        };
        let rsa_encrypted_aes_key = base64::decode(&base64_aes_key)?;
        let aes_key = private_key.decrypt(PADDING, &rsa_encrypted_aes_key)?;
        decrypt_secret(&secret_name, &encrypted_secret, &aes_key)
    }

    pub fn delete_secret(&mut self, secret_name: &str) -> Result<(), VaultfileError> {
        if !self.secrets.contains_key(secret_name) {
            return Err(VaultfileError {
                kind: VaultfileErrorKind::SecretNotFound(String::from(secret_name)),
            });
        }
        self.secrets.remove(secret_name);
        Ok(())
    }

    pub fn save_to_file(&self, vaultfile_path: &Path) -> Result<(), VaultfileError> {
        let vaultfile_json = serde_json::to_string_pretty(&self)?;
        let vaultfile_json = Vaultfile::move_keys_into_one_line(vaultfile_json);
        write_json_to_file(vaultfile_path, vaultfile_json, true)?;
        Ok(())
    }

    fn move_keys_into_one_line(ugly_vaultfile: String) -> String {
        let vaultfile_lines = ugly_vaultfile.lines();
        let mut pretty_vaultfile_lines: Vec<String> = Vec::with_capacity(1000);
        let mut current_line = String::with_capacity(1000);
        let mut inside_keys = false;
        let mut keys_found = false;
        let mut braces_level = 0;
        for line in vaultfile_lines {
            let trimmed_line = if current_line.is_empty() {
                line.to_string()
            } else {
                line.trim().replace(" ", &"")
            };
            current_line.push_str(&trimmed_line);
            if inside_keys {
                if line.contains("{") {
                    braces_level += 1;
                }
                if line.contains("}") {
                    braces_level -= 1;
                }
                if braces_level < 0 {
                    inside_keys = false;
                }
            }
            if !inside_keys || braces_level == 0 {
                pretty_vaultfile_lines.push(current_line);
                current_line = String::with_capacity(1000);
            }
            if !keys_found && line.ends_with("\"keys\": {") {
                inside_keys = true;
                keys_found = true;
            }
        }
        pretty_vaultfile_lines.join("\n")
    }
}

struct EncryptionResult {
    aes_key: [u8; 32],
    encrypted_base: String,
}

fn encrypt_base64_string(plaintext_base64: &str) -> Result<EncryptionResult, base64::DecodeError> {
    let raw_plaintext = base64::decode(plaintext_base64)?;
    Ok(encrypt_byte_sequence(&raw_plaintext))
}

fn encrypt_utf8_string(plaintext_utf8: &str) -> EncryptionResult {
    encrypt_byte_sequence(plaintext_utf8.as_bytes())
}

fn encrypt_byte_sequence(plaintext: &[u8]) -> EncryptionResult {
    let mut key: [u8; 32] = [0u8; 32];
    let mut rng = rand_chacha::ChaChaRng::from_entropy();
    rng.fill_bytes(&mut key);
    let encryptor = AesSafe256EncryptorX8::new(&key);
    let plaintext_length_bytes = (plaintext.len() as u64).to_le_bytes();
    let full_plaintext_length = plaintext_length_bytes.len() + plaintext.len();
    let padding_length = 128 - full_plaintext_length % 128;
    let mut plaintext_padding = vec![0; padding_length];
    rng.fill_bytes(&mut plaintext_padding);
    let mut full_plaintext: Vec<u8> = Vec::with_capacity(
        plaintext_length_bytes.len() + plaintext.len() + plaintext_padding.len(),
    );
    for byte in plaintext_length_bytes
        .iter()
        .chain(plaintext.into_iter())
        .chain((&plaintext_padding).into_iter())
    {
        full_plaintext.push(byte.clone());
    }
    let mut ciphertext = vec![0; full_plaintext.len()];
    encryptor.encrypt_block_x8(&full_plaintext, &mut ciphertext);
    let ciphertext_base64 = base64::encode(&ciphertext);
    EncryptionResult {
        aes_key: key,
        encrypted_base: ciphertext_base64,
    }
}

fn decrypt_secret(
    secret_name: &str,
    secret_base64: &str,
    key: &[u8],
) -> Result<String, VaultfileError> {
    let decryptor = AesSafe256DecryptorX8::new(key);
    let ciphertext = match base64::decode(secret_base64) {
        Ok(data) => data,
        Err(_) => {
            return {
                Err(VaultfileError {
                    kind: VaultfileErrorKind::BadBase64Secret(String::from(secret_name)),
                })
            }
        }
    };
    let mut plaintext = vec![0; ciphertext.len()];
    decryptor.decrypt_block_x8(&ciphertext, &mut plaintext);
    let plaintext_size: [u8; 8] = match plaintext[0..8].try_into() {
        Ok(size) => size,
        Err(_) => {
            return Err(VaultfileError {
                kind: VaultfileErrorKind::CorruptDataInSecret(String::from(secret_name)),
            })
        }
    };
    let plaintext_size = u64::from_le_bytes(plaintext_size);
    plaintext = plaintext[8..].to_vec();
    plaintext.truncate(plaintext_size as usize);
    match String::from_utf8(plaintext) {
        Ok(decrypted_secret) => Ok(decrypted_secret),
        Err(_) => {
            return Err(VaultfileError {
                kind: VaultfileErrorKind::CorruptDataInSecret(String::from(secret_name)),
            })
        }
    }
}

pub fn load_private_key(private_key_path: &Path) -> Result<RsaPrivateKey, VaultfileError> {
    if !private_key_path.is_file() {
        return Err(VaultfileError {
            kind: VaultfileErrorKind::PrivateKeyNotFound,
        });
    }
    let private_key_json = load_json_from_file(private_key_path)?;
    let private_key: RsaPrivateKey = serde_json::from_str(&private_key_json)?;
    Ok(private_key)
}

pub fn load_public_key(public_key_path: &Path) -> Result<RsaPublicKey, VaultfileError> {
    let public_key_json = load_json_from_file(public_key_path)?;
    parse_public_key(&public_key_json)
}

pub fn parse_public_key(public_key_json: &str) -> Result<RsaPublicKey, VaultfileError> {
    let public_key: RsaPublicKey = serde_json::from_str(&public_key_json)?;
    Ok(public_key)
}

pub fn public_key_to_json(public_key: &RsaPublicKey) -> Result<String, serde_json::Error> {
    serde_json::to_string(public_key)
}

pub fn load_json_from_file(json_file_path: &Path) -> Result<String, std::io::Error> {
    let mut json_file = File::open(json_file_path)?;
    let mut json_string = String::new();
    json_file.read_to_string(&mut json_string)?;
    Ok(json_string)
}

fn write_json_to_file(
    json_file_path: &Path,
    json: String,
    overwrite: bool,
) -> Result<(), std::io::Error> {
    let mut open_options = std::fs::OpenOptions::new();
    open_options.write(true);
    if overwrite {
        open_options.create(true).truncate(true);
    } else {
        open_options.create_new(true);
    }
    open_options
        .open(json_file_path)?
        .write_all(json.as_bytes())
}

#[cfg(test)]
mod vaultfile_tests {

    use super::*;

    #[test]
    fn key_generation() {
        let mut rng = rand_chacha::ChaChaRng::from_entropy();
        let filename = format!("priv_{}.key", rng.next_u32());
        Vaultfile::generate_and_save_key(Path::new(&filename)).unwrap();
        load_private_key(Path::new(&filename)).expect("Private key could not be loaded from file!");
        let public_key_name = format!("{}.pub", &filename);
        load_public_key(Path::new(&public_key_name))
            .expect("Public key could not be loaded from file!");
        std::fs::remove_file(filename).unwrap();
        std::fs::remove_file(public_key_name).unwrap();
    }

    #[test]
    fn test_json_file_write() {
        let mut rng = rand_chacha::ChaChaRng::from_entropy();
        let filename = format!("json{}.key", rng.next_u32());
        print!("Test writing to file {}", &filename);
        super::write_json_to_file(Path::new(&filename), String::from("{\"test\": 123}"), false)
            .expect("The file could not be written!");
        match super::write_json_to_file(
            Path::new(&filename),
            String::from("{\"test\": 123}"),
            false,
        ) {
            Ok(_) => panic!(
                "The file {} was overwritten without it being allowed!",
                &filename
            ),
            Err(_) => (),
        };
        match super::write_json_to_file(Path::new(&filename), String::from("{\"test\": 123}"), true)
        {
            Ok(_) => (),
            Err(_) => panic!(
                "The file {} was NOT overwritten when it was allowed!",
                &filename
            ),
        };
        std::fs::remove_file(filename).unwrap();
    }

    #[test]
    fn test_secret_write_and_read() {
        let mut rng = rand_chacha::ChaChaRng::from_entropy();
        let id = rng.next_u32();
        let vault_filename = format!("test{}.vault", id);
        let secret_key = "test_secret";
        let secret = "SECRET_VALUE_12345";
        let mut vaultfile = Vaultfile::new();
        let private_key = Vaultfile::generate_key();
        vaultfile
            .register_key("test_key", private_key.to_public_key(), &private_key)
            .unwrap();
        vaultfile.add_secret_utf8(secret_key, secret).unwrap();
        vaultfile.save_to_file(Path::new(&vault_filename)).unwrap();
        let vaultfile_to_check = Vaultfile::load_from_file(Path::new(&vault_filename)).unwrap();
        let recovered_secret = vaultfile_to_check
            .read_secret(secret_key, &private_key)
            .unwrap();
        assert_eq!(secret, recovered_secret);
        std::fs::remove_file(vault_filename).unwrap();
    }
}

#[derive(Debug)]
pub struct VaultfileError {
    pub kind: VaultfileErrorKind,
}

#[derive(Debug)]
pub enum VaultfileErrorKind {
    IoError(std::io::Error),
    InvalidJson(serde_json::error::Error),
    EncryptionError(rsa::errors::Error),
    VaultfileNotFound,
    PrivateKeyNotFound,
    // no private key was specified and it was required
    NoPrivateKeySpecified,
    // the private key specified is not registered in the vaultfile
    PrivateKeyNotRegistered,

    // Malformed vaultfile JSON errors:
    /// The secret with the name specified does not have
    /// an encrypted_key entry for all the keys registered in the vaultfile
    /// (the String parameter will have the name of the offending secret)
    SecretNotSharedWithAllRegisteredKeys(String),

    VaultfileMustHaveKeys,
    VaultfileKeyNotRegistered(String),
    BadBase64String(String),
    BadBase64Secret(String),
    SecretNotFound(String),
    CorruptDataInSecret(String),
}

impl From<std::io::Error> for VaultfileError {
    fn from(err: std::io::Error) -> VaultfileError {
        VaultfileError {
            kind: VaultfileErrorKind::IoError(err),
        }
    }
}

impl From<serde_json::error::Error> for VaultfileError {
    fn from(err: serde_json::error::Error) -> VaultfileError {
        VaultfileError {
            kind: VaultfileErrorKind::InvalidJson(err),
        }
    }
}

impl From<rsa::errors::Error> for VaultfileError {
    fn from(err: rsa::errors::Error) -> VaultfileError {
        VaultfileError {
            kind: VaultfileErrorKind::EncryptionError(err),
        }
    }
}

impl From<base64::DecodeError> for VaultfileError {
    fn from(err: base64::DecodeError) -> VaultfileError {
        VaultfileError {
            kind: VaultfileErrorKind::BadBase64String(format!("{}", err)),
        }
    }
}
