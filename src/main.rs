mod vaultfile;

use std::path::Path;
use std::process::exit;
use vaultfile::{load_private_key, load_public_key, parse_public_key, public_key_to_json};
use vaultfile::{Vaultfile, VaultfileErrorKind};

extern crate clap;
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};

fn get_home_directory() -> String {
    match std::env::var("HOME") {
        Ok(home_dir_path) => home_dir_path,
        Err(_) => match std::env::var("USERPROFILE") {
            Ok(windows_home_dir) => windows_home_dir,
            Err(_) => {
                eprintln!("Neither $HOME (Unix) or %USERPROFILE% (Windows) environment variables could be found!");
                exit(exitcode::CONFIG);
            }
        },
    }
}

fn get_username() -> String {
    match std::env::var("USER") {
        Ok(home_dir_path) => home_dir_path,
        Err(_) => match std::env::var("USERNAME") {
            Ok(windows_home_dir) => windows_home_dir,
            Err(_) => {
                eprintln!("Neither $USER (Unix) or %USERNAME% (Windows) environment variables could be found!");
                exit(exitcode::CONFIG);
            }
        },
    }
}

fn get_default_vaultfile_folder() -> String {
    let xdg_config_home = match std::env::var("XDG_CONFIG_HOME") {
        Ok(xdg_config_home) => xdg_config_home,
        Err(_) => String::from(
            Path::new(&get_home_directory())
                .join(".config")
                .to_str()
                .expect("Error while creating vaultfile path!"),
        ),
    };
    String::from(
        Path::new(&xdg_config_home)
            .join("vaultfile")
            .to_str()
            .expect("Error while creating vaultfile path!"),
    )
}

fn ensure_vaultfile_folder_exists() {
    let vaultfile_folder_path = get_default_vaultfile_folder();
    let vaultfile_folder = Path::new(&vaultfile_folder_path);
    if vaultfile_folder.is_dir() {
        return;
    }
    if vaultfile_folder.is_file() {
        eprintln!(
            "There is a file instead of a folder at {}",
            &vaultfile_folder_path
        );
        exit(exitcode::CANTCREAT);
    }
    match std::fs::create_dir_all(&vaultfile_folder_path) {
        Ok(_) => (),
        Err(error) => {
            eprintln!(
                "Error while creating {} folder: {:?}",
                vaultfile_folder_path, error
            );
            exit(exitcode::CANTCREAT);
        }
    };
}

enum Confirmation {
    YES,
    NO,
}

fn read_user_confirmation(message: String) -> Confirmation {
    println!("{} (yes/y or no/n)", &message);
    let mut overwrite = String::new();
    match std::io::stdin().read_line(&mut overwrite) {
        Ok(_) => (),
        Err(_) => {
            eprintln!("Failed to read confirmation from user!");
            exit(exitcode::DATAERR);
        }
    }
    if overwrite.starts_with("y") {
        return Confirmation::YES;
    }
    if overwrite.starts_with("n") {
        return Confirmation::NO;
    }
    eprintln!("You must type yes or no!");
    exit(exitcode::DATAERR);
}

fn check_file_overwrite(file_to_check: &str, overwrite_no: bool) {
    if Path::new(&file_to_check).exists() {
        if overwrite_no {
            eprintln!("File at '{}' already exists, and no overwriting has been selected. Doing nothing...", &file_to_check);
            exit(exitcode::OK);
        }
        match read_user_confirmation(format!(
            "File at '{}' already exists. Overwrite?",
            &file_to_check
        )) {
            Confirmation::YES => return,
            Confirmation::NO => {
                eprintln!("File at '{}' already exists, and no overwriting has been selected. Doing nothing...", &file_to_check);
                exit(exitcode::OK);
            }
        }
    }
}

fn load_or_create_vaultfile(vaultfile_path: &str) -> Vaultfile {
    load_vaultfile(vaultfile_path, false)
}

fn load_existing_vaultfile(vaultfile_path: &str) -> Vaultfile {
    load_vaultfile(vaultfile_path, true)
}

fn load_vaultfile(vaultfile_path: &str, must_exist: bool) -> Vaultfile {
    match Vaultfile::load_from_file(vaultfile_path) {
        Ok(vaultfile) => vaultfile,
        Err(error) => match error.kind {
            VaultfileErrorKind::VaultfileNotFound => {
                if must_exist {
                    eprintln!("No vaultfile found at {}!", vaultfile_path);
                    exit(exitcode::NOINPUT);
                }
                Vaultfile::new()
            }
            VaultfileErrorKind::InvalidJson(json_error) => {
                eprintln!("Malformed/corrupt vaultfile! Error: {:?}", json_error);
                exit(exitcode::DATAERR);
            }
            VaultfileErrorKind::VaultfileMustHaveKeys => {
                eprintln!("Malformed/corrupt vaultfile! It has no registered keys!");
                exit(exitcode::DATAERR);
            }
            VaultfileErrorKind::SecretNotSharedWithAllRegisteredKeys(secret_name) => {
                eprintln!("Malformed/corrupt vaultfile! Secret {} is not shared with all registered keys!", secret_name);
                exit(exitcode::DATAERR);
            }
            _ => panic!("Unexpected error! {:?}", error),
        },
    }
}

fn generate_key_command(cli_call: &ArgMatches) {
    let key_path = if cli_call.is_present("key-path") {
        // we can simply unwrap because clap verifies that a value has been provided
        String::from(cli_call.value_of("key-path").unwrap())
    } else if cli_call.is_present("key-name") {
        ensure_vaultfile_folder_exists();
        String::from(
            Path::new(&get_default_vaultfile_folder())
                .join(format!("{}.key", &cli_call.value_of("key-name").unwrap()))
                .to_str()
                .expect("Invalid home directory!"),
        )
    } else {
        ensure_vaultfile_folder_exists();
        String::from(
            Path::new(&get_default_vaultfile_folder())
                .join(format!("{}.key", &get_username()))
                .to_str()
                .expect("Invalid home directory!"),
        )
    };
    if !cli_call.is_present("overwrite-yes") {
        check_file_overwrite(&key_path, cli_call.is_present("overwrite-no"));
    }
    Vaultfile::generate_new_key(&key_path).unwrap_or_else(|error| {
        match error.kind {
            VaultfileErrorKind::IoError(io_error) => {
                eprintln!("I/O Error: {:?}", io_error);
                match io_error.kind() {
                    std::io::ErrorKind::NotFound => exit(exitcode::CANTCREAT),
                    std::io::ErrorKind::PermissionDenied => exit(exitcode::NOPERM),
                    _ => exit(exitcode::IOERR),
                }
            }
            _ => panic!("Unexpected error: {:?}", error),
        };
    });
    println!("The private key has been generated and saved.");
    println!(
        "It is up to you to ensure that the private key at {}, stays private!",
        key_path
    );
    if cfg!(unix) {
        println!("It is recommended that you make it accessible only for you, with the following command:");
        println!("$ chmod 600 {}", key_path);
        println!("It would be even better if you made it read-only (to prevent accidental deletion), with:");
        println!("$ chmod 400 {}", key_path);
    }
}

fn register_key_command(cli_call: &ArgMatches) {
    // These two parameters will be there for sure (Clap validates it)
    let vaultfile_path = cli_call.value_of("file").unwrap();
    let key_name = cli_call.value_of("key-name").unwrap();
    let new_key = match cli_call.value_of("key-json") {
        Some(json) => parse_public_key(json),
        None => match cli_call.value_of("key-file") {
            Some(json_filename) => load_public_key(json_filename),
            None => {
                eprintln!("Either 'key-name' or 'key-file' must be specified!");
                exit(exitcode::USAGE);
            }
        },
    };
    // there will always be at least a default value
    let private_key_path = String::from(
        Path::new(&get_default_vaultfile_folder())
            .join(format!(
                "{}.key",
                cli_call.value_of("private-key-name").unwrap()
            ))
            .to_str()
            .expect(&format!("Invalid path {}", &get_default_vaultfile_folder())),
    );
    let private_key = match load_private_key(&private_key_path) {
        Ok(priv_key) => Some(priv_key),
        Err(error) => match error.kind {
            VaultfileErrorKind::PrivateKeyNotFound => None,
            VaultfileErrorKind::InvalidJson(serde_error) => {
                eprintln!(
                    "Bad private key data found in file {}! {:?}",
                    &private_key_path, serde_error
                );
                exit(exitcode::DATAERR);
            }
            _ => panic!("Error when loading specified private key!"),
        },
    };
    let new_key = match new_key {
        Ok(public_key) => public_key,
        Err(error) => match error.kind {
            VaultfileErrorKind::IoError(io_error) => {
                eprintln!(
                    "I/O Error when reading public key from file system! {:?}",
                    io_error
                );
                exit(exitcode::IOERR);
            }
            VaultfileErrorKind::InvalidJson(serde_error) => {
                eprintln!("Invalid RSA public key JSON string: {:?}", serde_error);
                exit(exitcode::DATAERR);
            }
            err_kind => panic!("Unexpected error! {:?}", err_kind),
        },
    };
    let mut vaultfile = load_or_create_vaultfile(&vaultfile_path);
    if !cli_call.is_present("overwrite-yes") {
        if vaultfile.is_key_registered(key_name) {
            if cli_call.is_present("overwrite-no") {
                eprintln!("The vaultfile at '{}' already has a key registered under name {}, and no overwriting has been selected. Doing nothing...", &vaultfile_path, &key_name);
                exit(exitcode::OK);
            }
            match read_user_confirmation(format!(
                "Vaultfile at '{}' already has a key registered under name {}. Overwrite?",
                &vaultfile_path, &key_name
            )) {
                Confirmation::YES => return,
                Confirmation::NO => {
                    eprintln!("The vaultfile at '{}' already has a key registered under name {}, and no overwriting has been selected. Doing nothing...", &vaultfile_path, &key_name);
                    exit(exitcode::OK);
                }
            }
        }
    }
    vaultfile.register_key(&key_name, new_key, private_key).unwrap_or_else(|error| {
        match error.kind {
            VaultfileErrorKind::PrivateKeyNotRegistered => {
                eprintln!("The private key you specified is not registered in the vaultfile! (and is therefore useless for sharing the secrets with another key/person)");
                exit(exitcode::DATAERR);
            },
            _ => panic!("Unexpected error! {:?}", error),
        }
    });
    vaultfile
        .save_to_file(&vaultfile_path)
        .unwrap_or_else(|error| match error.kind {
            _ => panic!("Unexpected error: {:?}", error),
        });
    println!(
        "New key registered in vaultfile at {} under name {}.",
        &vaultfile_path, &key_name
    );
}

fn list_keys_command(cli_call: &ArgMatches) {
    let vaultfile_path = cli_call.value_of("file").unwrap();
    let vaultfile = load_existing_vaultfile(vaultfile_path);
    for registered_key_name in vaultfile.list_keys() {
        println!("{}", registered_key_name);
    }
}

fn list_secrets_command(cli_call: &ArgMatches) {
    let vaultfile_path = cli_call.value_of("file").unwrap();
    let vaultfile = load_existing_vaultfile(vaultfile_path);
    for registered_key_name in vaultfile.list_secrets() {
        println!("{}", registered_key_name);
    }
}

fn show_key_command(cli_call: &ArgMatches) {
    let vaultfile_path = cli_call.value_of("file").unwrap();
    let name_of_key_to_show = cli_call.value_of("key-name").unwrap();
    let vaultfile = load_existing_vaultfile(vaultfile_path);
    match vaultfile.get_key(name_of_key_to_show) {
        Some(key) => println!(
            "{}",
            match public_key_to_json(&key) {
                Ok(key_json) => key_json,
                Err(serde_error) => panic!("Key data is corrupt! {:?}", serde_error),
            }
        ),
        None => {
            eprintln!(
                "No key named '{}' was found in the vaultfile at {}",
                name_of_key_to_show, vaultfile_path
            );
            exit(exitcode::DATAERR);
        }
    }
}

fn deregister_key_command(cli_call: &ArgMatches) {
    let vaultfile_path = cli_call.value_of("file").unwrap();
    let name_of_key_to_remove = cli_call.value_of("key-name").unwrap();
    let mut vaultfile = load_existing_vaultfile(vaultfile_path);
    vaultfile
        .deregister_key(name_of_key_to_remove)
        .unwrap_or_else(|error| {
            eprintln!(
                "Unexpected error when deregistering key '{}' from vaultfile at {}! {:?}",
                name_of_key_to_remove, vaultfile_path, error
            );
            exit(exitcode::SOFTWARE);
        });
    vaultfile
        .save_to_file(vaultfile_path)
        .unwrap_or_else(|error| {
            eprintln!(
                "Unexpected error when saving vaultfile after executing key deregistration! {:?}",
                error
            );
            exit(exitcode::IOERR);
        })
}

fn add_secret_command(cli_call: &ArgMatches) {
    let vaultfile_path = cli_call.value_of("file").unwrap();
    let secret_name = cli_call.value_of("name").unwrap();
    let secret_value_utf8 = cli_call.value_of("value");
    let secret_value_base64 = cli_call.value_of("base64-value");
    let mut vaultfile = load_existing_vaultfile(vaultfile_path);
    if !cli_call.is_present("overwrite-yes") {
        if vaultfile.has_secret_named(secret_name) {
            if cli_call.is_present("overwrite-no") {
                eprintln!("The vaultfile at '{}' already has a secret registered under name {}, and no overwriting has been selected. Doing nothing...", &vaultfile_path, &secret_name);
                exit(exitcode::OK);
            }
            match read_user_confirmation(format!(
                "Vaultfile at '{}' already has a secret registered under name {}. Overwrite?",
                &vaultfile_path, &secret_name
            )) {
                Confirmation::YES => return,
                Confirmation::NO => {
                    eprintln!("The vaultfile at '{}' already has a secret registered under name {}, and no overwriting has been selected. Doing nothing...", &vaultfile_path, &secret_name);
                    exit(exitcode::OK);
                }
            }
        }
    }
    (match secret_value_utf8 {
        Some(utf8_secret) => {
            vaultfile.add_secret_utf8(secret_name, utf8_secret)
        },
        None => match secret_value_base64 {
            Some(base64_secret) => {
                vaultfile.add_secret_base64(secret_name, base64_secret)
            },
            None => {
                panic!("Clap should have enforced that either --value or --base64-value was provided!");
            }
        }
    }).unwrap_or_else(|error| {
        eprintln!("Unexpected error while adding secret to vaultfile! {:?}", error);
        exit(exitcode::SOFTWARE);
    });
    vaultfile
        .save_to_file(vaultfile_path)
        .unwrap_or_else(|error| {
            eprintln!(
                "Unexpected error when saving vaultfile after executing key deregistration! {:?}",
                error
            );
            exit(exitcode::IOERR);
        })
}

fn read_secret_command(cli_call: &ArgMatches) {
    let vaultfile_path = cli_call.value_of("file").unwrap();
    let secret_name = cli_call.value_of("name").unwrap();
    let private_key_path = match cli_call.value_of("key-file") {
        Some(key_path) => String::from(key_path),
        None => {
            let key_name = cli_call.value_of("key-name").unwrap();
            String::from(
                Path::new(&get_default_vaultfile_folder())
                    .join(format!("{}.key", &key_name))
                    .to_str()
                    .expect(&format!("Invalid path {}", &get_default_vaultfile_folder())),
            )
        }
    };
    let private_key = match load_private_key(&private_key_path) {
        Ok(key) => key,
        Err(error) => match error.kind {
            VaultfileErrorKind::PrivateKeyNotFound => {
                eprintln!("No private key was found at {}!", &private_key_path);
                exit(exitcode::NOINPUT);
            }
            _ => panic!("Unexpected error when loading private_key file!"),
        },
    };
    let vaultfile = load_existing_vaultfile(vaultfile_path);
    match vaultfile.read_secret(secret_name, private_key) {
        Ok(secret_value) => {
            if cli_call.is_present("no-eol") {
                print!("{}", secret_value);
            } else {
                println!("{}", secret_value);
            }
        }
        Err(error) => {
            panic!(
                "Unexpected error when reading secret value from vaultfile: {:?}",
                error
            );
        }
    }
}

fn delete_secret_command(cli_call: &ArgMatches) {
    let vaultfile_path = cli_call.value_of("file").unwrap();
    let secret_name = cli_call.value_of("name").unwrap();
    let mut vaultfile = load_existing_vaultfile(vaultfile_path);
    vaultfile
        .delete_secret(secret_name)
        .unwrap_or_else(|error| match error.kind {
            VaultfileErrorKind::SecretNotFound(_sec_name) => {
                eprintln!("No secret found with name '{}'!", secret_name);
                exit(exitcode::DATAERR);
            }
            _ => panic!("Unexpected error! {:?}", error),
        });
    vaultfile
        .save_to_file(vaultfile_path)
        .unwrap_or_else(|error| {
            eprintln!("Unexpected error while saving vaultfile! {:?}", error);
            exit(exitcode::IOERR);
        });
}

fn main() {
    let username = get_username();
    let cli_call = App::new("vaultfile")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .setting(AppSettings::ArgRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("generate-key")
                .about("Generate a new private key")
                .arg(
                    Arg::with_name("key-name")
                        .long("key-name")
                        .takes_value(true)
                        .conflicts_with("key-path")
                        .help(
                            &format!("Name of the keyfile to generate under {} (your username will be used by default)",
                                get_default_vaultfile_folder())
                        ),
                )
                .arg(
                    Arg::with_name("key-path")
                        .long("key-path")
                        .takes_value(true)
                        .conflicts_with("key-name")
                        .help("Path of the file to place the generated key in."),
                )
                .arg(
                    Arg::with_name("overwrite-yes")
                    .short("y")
                    .long("yes")
                    .takes_value(false)
                    .help("Set this option to overwrite the key file if it already exists.")
                )
                .arg(
                    Arg::with_name("overwrite-no")
                    .short("n")
                    .long("no")
                    .takes_value(false)
                    .help("Set this option to NOT overwrite the key file if it already exists")
                )
        )
        .subcommand(
            SubCommand::with_name("register-key")
                .about("Register a key in a vaultfile, creating the vaultfile if it does not exist.")
                .arg(
                    Arg::with_name("file")
                    .short("f")
                    .long("file")
                    .takes_value(true)
                    .required(true)
                    .help("The vaultfile to register the key in (it will be created if it does not exist).")
                )
                .arg(
                    Arg::with_name("key-name")
                    .long("key-name")
                    .takes_value(true)
                    .required(true)
                    .help("The name with which you want to register the key in the vaultfile (if it exists, it will be overwritten).")
                )
                .arg(
                    Arg::with_name("key-file")
                    .long("key-file")
                    .takes_value(true)
                    .conflicts_with("key-json")
                    .required_unless("key-json")
                    .help("The file containing the public key you wish to register in the vaultfile (path must be absolute or relative to current directory).")
                )
                .arg(
                    Arg::with_name("key-json")
                    .long("key-json")
                    .takes_value(true)
                    .conflicts_with("key-file")
                    .required_unless("key-file")
                    .help("A JSON string containing the public key you wish to register in the vaultfile.")
                )
                .arg(
                    Arg::with_name("private-key-name")
                    .long("private-key-name")
                    .takes_value(true)
                    .default_value(&username)
                    .help("The name of a valid private key, used to share all the secrets in the vaultfile with the newly registered public key. It is only used when there are secrets saved in the vaultfile. It will look for the key in the default folder.")
                )
                .arg(
                    Arg::with_name("overwrite-yes")
                    .short("y")
                    .long("yes")
                    .takes_value(false)
                    .help("Set this option to overwrite the key in the vaultfile if it is already registered.")
                )
                .arg(
                    Arg::with_name("overwrite-no")
                    .short("n")
                    .long("no")
                    .takes_value(false)
                    .help("Set this option to NOT overwrite the key in the vaultfile if it is already registered.")
                )
        )
        .subcommand(
            SubCommand::with_name("list-keys")
            .about("List all the keys registered in the vaultfile.")
            .arg(
                Arg::with_name("file")
                .long("file")
                .short("f")
                .takes_value(true)
                .required(true)
                .help("The path of the vaultfile to use.")
            )
        )
        .subcommand(
            SubCommand::with_name("list-secrets")
            .about("List all the secrets registered in the vaultfile.")
            .arg(
                Arg::with_name("file")
                .long("file")
                .short("f")
                .takes_value(true)
                .required(true)
                .help("The path of the vaultfile to use.")
            )
        )
        .subcommand(
            SubCommand::with_name("show-key")
            .about("Prints out the JSON-encoded public key registered in the specified vaultfile (to stdout).")
            .arg(
                Arg::with_name("file")
                .long("file")
                .short("f")
                .takes_value(true)
                .required(true)
                .help("The path of the vaultfile to use.")
            )
            .arg(
                Arg::with_name("key-name")
                .long("key-name")
                .takes_value(true)
                .required(true)
                .help("The name of the key to show.")
            )
        )
        .subcommand(
            SubCommand::with_name("deregister-key")
            .about("Removes a registered public key from the vaultfile (and removes all of the values encrypted with that public key from the vaultfile).")
            .arg(
                Arg::with_name("file")
                .long("file")
                .short("f")
                .takes_value(true)
                .required(true)
                .help("The path of the vaultfile to use.")
            )
            .arg(
                Arg::with_name("key-name")
                .long("key-name")
                .takes_value(true)
                .required(true)
                .help("The name of the key to remove.")
            )
        )
        .subcommand(
            SubCommand::with_name("add-secret")
            .about("Add a secret to the vaultfile.")
            .arg(
                Arg::with_name("file")
                .long("file")
                .short("f")
                .takes_value(true)
                .required(true)
                .help("The path of the vaultfile to store the new secret in.")
            )
            .arg(
                Arg::with_name("name")
                .long("name")
                .short("n")
                .takes_value(true)
                .required(true)
                .help("The name under which to store the secret.")
            )
            .arg(
                Arg::with_name("value")
                .long("value")
                .short("v")
                .takes_value(true)
                .required_unless("base64-value")
                .help("The secret value to store in the vaultfile (assumed to be a utf8-encoded string).")
            )
            .arg(
                Arg::with_name("base64-value")
                .long("base64-value")
                .takes_value(true)
                .required_unless("value")
                .help("The secret value to store in the vaultfile, encoded as a base64 string. This is useful for storing binary-sensitive data in a reliable way, or data that is difficult to escape for inclusion in a shell command.")
            )
        )
        .subcommand(
            SubCommand::with_name("read-secret")
            .about("Read a secret saved in the vaultfile.")
            .arg(
                Arg::with_name("file")
                .long("file")
                .short("f")
                .takes_value(true)
                .required(true)
                .help("The path of the vaultfile to store the new secret in.")
            )
            .arg(
                Arg::with_name("name")
                .long("name")
                .short("n")
                .takes_value(true)
                .required(true)
                .help("The name of the secret to read.")
            )
            .arg(
                Arg::with_name("key-name")
                .long("key-name")
                .short("k")
                .takes_value(true)
                .conflicts_with("key-file")
                .default_value(&username)
                .help("The name of the private key to use to read the secret (it does not need to be registered under the same name in the vaultfile).")
                .long_help(&format!("The name of the private key to use to read the secret (it does not need to be registered under the same name in the vaultfile).
                    It must be present as <key_name>.key under the {} directory in your home directory, and must be registered in the vaultfile.",
                    get_default_vaultfile_folder()))
            )
            .arg(
                Arg::with_name("key-file")
                .long("key-file")
                .takes_value(true)
                .conflicts_with("key-name")
                .help("A file containing a private key which can access secrets in the vaultfile.")
            )
            .arg(
                Arg::with_name("no-eol")
                .long("no-eol")
                .takes_value(false)
                .help("Set this option to not print an end-of-line character after printing the secret value.")
            )
        )
        .subcommand(
            SubCommand::with_name("delete-secret")
            .about("Delete a secret from the specified vaultfile.")
            .arg(
                Arg::with_name("file")
                .long("file")
                .short("f")
                .takes_value(true)
                .required(true)
                .help("The vaultfile to delete the secret from.")
            )
            .arg(
                Arg::with_name("name")
                .long("name")
                .short("n")
                .takes_value(true)
                .required(true)
                .help("The name of the secret to delete from the vaultfile.")
            )
        )
        .get_matches_safe();

    let cli_call = match cli_call {
        Ok(call) => call,
        Err(error) => match error.kind {
            clap::ErrorKind::HelpDisplayed => error.exit(),
            clap::ErrorKind::VersionDisplayed => error.exit(),
            _ => {
                eprintln!("{}", error.message);
                exit(exitcode::USAGE);
            }
        },
    };

    if let Some(cli_call) = cli_call.subcommand_matches("generate-key") {
        generate_key_command(cli_call);
    } else if let Some(cli_call) = cli_call.subcommand_matches("register-key") {
        register_key_command(cli_call);
    } else if let Some(cli_call) = cli_call.subcommand_matches("list-keys") {
        list_keys_command(cli_call);
    } else if let Some(cli_call) = cli_call.subcommand_matches("list-secrets") {
        list_secrets_command(cli_call);
    } else if let Some(cli_call) = cli_call.subcommand_matches("show-key") {
        show_key_command(cli_call);
    } else if let Some(cli_call) = cli_call.subcommand_matches("deregister-key") {
        deregister_key_command(cli_call);
    } else if let Some(cli_call) = cli_call.subcommand_matches("add-secret") {
        add_secret_command(cli_call);
    } else if let Some(cli_call) = cli_call.subcommand_matches("read-secret") {
        read_secret_command(cli_call);
    } else if let Some(cli_call) = cli_call.subcommand_matches("delete-secret") {
        delete_secret_command(cli_call);
    }
    exit(exitcode::OK);
}
