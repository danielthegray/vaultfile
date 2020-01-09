pub mod vaultfile {

    extern crate base64;
    extern crate rand;
    extern crate rsa;

    use rand::RngCore;
    use rsa::{PaddingScheme, PublicKey, RSAPrivateKey, RSAPublicKey};

    use aes_soft::block_cipher_trait::generic_array::GenericArray;
    use aes_soft::block_cipher_trait::BlockCipher;
    use aes_soft::Aes256;

    use std::collections::HashMap;
    use std::fs::File;
    use std::io::prelude::{Read, Write};

    use serde::{Deserialize, Serialize};

    const pkcs: PaddingScheme = PaddingScheme::PKCS1v15;

    #[derive(Serialize, Deserialize)]
    pub struct VaultfileSecret {
        secret: String,
        // the encryption key to the secret is stored
        // under the name of the key used to encrypt it
        encrypted_key: HashMap<String, String>,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Vaultfile {
        keys: HashMap<String, RSAPublicKey>,
        // each secret is stored under a name
        secrets: HashMap<String, VaultfileSecret>,
    }

    impl Vaultfile {
        pub fn load_from_file(vaultfile_path: &str) -> Result<Vaultfile, VaultfileError> {
            let vaultfile_json = load_json_from_file(vaultfile_path)?;
            let vaultfile: Vaultfile = serde_json::from_str(&vaultfile_json)?;
            Ok(vaultfile)
        }

        pub fn generate_new_key(private_key_path: &str) {
            let public_key_path = format!("{}.pub", &private_key_path);
            let mut rng = rand::rngs::OsRng;
            let bits = 2048;
            let private_key = RSAPrivateKey::new(&mut rng, bits).expect("Failed to generate key!");
            let public_key = private_key.to_public_key();
            let private_key_json = serde_json::to_string(&private_key).unwrap();
            let public_key_json = serde_json::to_string(&public_key).unwrap();
            match write_json_to_file(private_key_path, private_key_json, false) {
                Ok(_) => (),
                Err(error) => panic!(error),
            }
            match write_json_to_file(&public_key_path, public_key_json, false) {
                Ok(_) => (),
                Err(error) => panic!(error),
            }
        }

        pub fn find_registered_name_of_key<T: PublicKey>(&self, key: T) -> Option<String> {
            for (key_name, registered_key) in self.keys.iter() {
                if registered_key.n() == key.n() && registered_key.e() == key.e() {
                    return Some(String::from(key_name));
                }
            }
            return None;
        }

        /// Registers a new key in the vaultfile, under a specified name.
        /// If a key under that name already exists, it will be overwritten.
        pub fn register_key(
            &mut self,
            name_new_key: &str,
            new_key: RSAPublicKey,
            private_key: Option<RSAPrivateKey>,
        ) -> Result<(), VaultfileError> {
            if self.secrets.len() > 0 {
                if private_key.is_none() {
                    return Err(VaultfileError {
                        kind: VaultfileErrorKind::NoPrivateKeySpecified,
                    });
                }
                let private_key = private_key.unwrap();
                let private_key_name = match self.find_registered_name_of_key(private_key) {
                    Some(key_name) => key_name,
                    None => {
                        return Err(VaultfileError {
                            kind: VaultfileErrorKind::PrivateKeyNotRegistered,
                        });
                    }
                };
                let mut rng = rand::rngs::OsRng;
                // we now grant access to all the shared secrets to the newly registered key
                for (secret_name, mut secret) in self.secrets.iter_mut() {
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
                    let raw_aes_key = private_key.decrypt(pkcs, &raw_encrypted_key)?;
                    // we encrypt the AES key using the newly registered public key
                    // to grant them access to the secret
                    let new_encrypted = new_key.encrypt(&mut rng, pkcs, &raw_aes_key)?;
                    let base64_encrypted_key = base64::encode(&new_encrypted);
                    secret
                        .encrypted_key
                        .insert(String::from(name_new_key), base64_encrypted_key);
                }
            }
            self.keys.insert(String::from(name_new_key), new_key);
            Ok(())
        }

        pub fn add_secret(
            &mut self,
            secret_name: &str,
            secret_value: &str,
        ) -> Result<(), VaultfileError> {
            let mut rng = rand::rngs::OsRng;
            let mut encrypted_key: HashMap<String, String> = HashMap::new();
            let encrypted_secret = encrypt_string(secret_value);
            for (key_name, rsa_key) in self.keys.iter() {
                let aes_key_ciphertext =
                    rsa_key.encrypt(&mut rng, pkcs, &encrypted_secret.aes_key)?;
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
            secret_name: String,
            private_key: RSAPrivateKey,
        ) -> Result<String, VaultfileError> {
            let key_name = match self.find_registered_name_of_key(private_key) {
                Some(name) => name,
                None => {
                    return Err(VaultfileError{
                        kind: VaultfileErrorKind::PrivateKeyNotRegistered,
                    })
                }
            };
            let secret_to_read = match self.secrets.get(&secret_name) {
                Some(secret) => secret,
                None => {
                    return Err(VaultfileError {
                        kind: VaultfileErrorKind::SecretNotFound(secret_name),
                    })
                }
            };
            let encrypted_secret = secret_to_read.secret;
            let base64_aes_key = match secret_to_read.encrypted_key.get(&key_name) {
                Some(b64_key) => b64_key,
                None => {return Err(VaultfileError{
                    kind: VaultfileErrorKind::SecretNotSharedWithAllRegisteredKeys(secret_name)
                })}
            };
            let rsa_encrypted_aes_key = base64::decode(&base64_aes_key)?;
            let aes_key = private_key.decrypt(pkcs, &rsa_encrypted_aes_key)?;
            decrypt_secret(&secret_name, &encrypted_secret, &aes_key)
        }

        pub fn save_to_file(&self, vaultfile_path: &str) -> Result<(), VaultfileError> {
            let vaultfile_json = serde_json::to_string_pretty(&self)?;
            write_json_to_file(vaultfile_path, vaultfile_json, true)?;
            Ok(())
        }
    }

    struct EncryptionResult {
        aes_key: [u8; 32],
        encrypted_base: String,
    }

    fn encrypt_string(plaintext: &str) -> EncryptionResult {
        let mut key: [u8; 32] = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let key_for_aes = GenericArray::clone_from_slice(&key);
        let cipher = Aes256::new(&key_for_aes);
        let plaintext_bytes = plaintext.as_bytes();
        let mut plaintext_bytes = GenericArray::clone_from_slice(plaintext_bytes);

        cipher.encrypt_block(&mut plaintext_bytes);
        let ciphertext_base64 = base64::encode(&plaintext_bytes);
        EncryptionResult {
            aes_key: key,
            encrypted_base: ciphertext_base64,
        }
    }

    fn decrypt_secret(secret_name: &str, secret_base64: &str, key: &[u8]) -> Result<String, VaultfileError> {
        let key_for_aes = GenericArray::clone_from_slice(key);
        let cipher = Aes256::new(&key_for_aes);
        let secret_bytes = match base64::decode(secret_base64) {
            Ok(data) => data,
            Err(_) => return {
                Err(VaultfileError{
                    kind: VaultfileErrorKind::BadBase64Secret(String::from(secret_name)),
                })
            }
        };
        let mut secret_bytes = GenericArray::clone_from_slice(&secret_bytes);
        cipher.decrypt_block(&mut secret_bytes);
        match String::from_utf8(secret_bytes.as_slice().to_vec()) {
            Ok(decrypted_secret) => Ok(decrypted_secret),
            Err(_) => return Err(VaultfileError{
                kind: VaultfileErrorKind::CorruptDataInSecret(String::from(secret_name)),
            })
        }
    }

    fn load_private_key(private_key_path: &str) -> Result<RSAPrivateKey, VaultfileError> {
        let private_key_json = load_json_from_file(private_key_path)?;
        let private_key: RSAPrivateKey = serde_json::from_str(&private_key_json)?;
        Ok(private_key)
    }

    fn load_json_from_file(json_file_path: &str) -> Result<String, std::io::Error> {
        let json_file = File::open(json_file_path)?;
        let mut json_string = String::new();
        json_file.read_to_string(&mut json_string)?;
        Ok(json_string)
    }

    fn write_json_to_file(
        json_file_path: &str,
        json: String,
        overwrite: bool,
    ) -> Result<(), std::io::Error> {
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(overwrite)
            .open(json_file_path)?
            .write_all(json.as_bytes())
    }

    #[cfg(test)]
    mod vaultfile_tests {

        use rand::RngCore;

        #[test]
        fn test_json_file_write() {
            let filename = format!("json{}.key", rand::thread_rng().next_u32());
            super::write_json_to_file(&filename, String::from("{\"test\": 123}"), false)
                .expect("The file could not be written!");
            match super::write_json_to_file(&filename, String::from("{\"test\": 123}"), false) {
                Ok(_) => panic!(
                    "The file {} was overwritten without it being allowed!",
                    &filename
                ),
                Err(error) => (),
            };
            match super::write_json_to_file(&filename, String::from("{\"test\": 123}"), true) {
                Ok(_) => (),
                Err(error) => panic!(
                    "The file {} was NOT overwritten when it was allowed!",
                    &filename
                ),
            };
        }
    }

    pub struct VaultfileError {
        kind: VaultfileErrorKind,
    }

    pub enum VaultfileErrorKind {
        IoError(std::io::Error),
        InvalidJson(serde_json::error::Error),
        EncryptionError(rsa::errors::Error),
        // no private key was specified and it was required
        NoPrivateKeySpecified,
        // the private key specified is not registered in the vaultfile
        PrivateKeyNotRegistered,

        // Malformed vaultfile JSON errors:

        // the secret with the name specified does not have
        // an encrypted_key entry for all the keys registered in
        // the vaultfile (the String parameter will have the secret name)
        SecretNotSharedWithAllRegisteredKeys(String),

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

    impl From<base64::Base64Error> for VaultfileError {
        fn from(err: base64::Base64Error) -> VaultfileError {
            VaultfileError {
                kind: VaultfileErrorKind::BadBase64String(format!("{}", err)),
            }
        }
    }
}
