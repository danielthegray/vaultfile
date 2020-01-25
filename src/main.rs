mod vaultfile;

use rsa::RSAPublicKey;
use std::path::Path;
use std::process::exit;
use vaultfile::VaultfileErrorKind;
use vaultfile::{load_private_key, load_public_key, parse_public_key, Vaultfile};

extern crate clap;
use clap::{App, Arg, ArgMatches, SubCommand};

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
    format!("{}/.vaultfile", &get_home_directory())
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
    match std::fs::create_dir(&vaultfile_folder_path) {
        Ok(_) => (),
        Err(error) => {
            eprintln!("Error while creating .vaultfile folder: {:?}", error);
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

fn generate_key_command(cli_call: &ArgMatches) {
    let key_path = if cli_call.is_present("key-path") {
        // we can simply unwrap because clap verifies that a value has been provided
        String::from(cli_call.value_of("key-path").unwrap())
    } else if cli_call.is_present("key-name") {
        ensure_vaultfile_folder_exists();
        format!(
            "{}/.vaultfile/{}.key",
            &get_home_directory(),
            &cli_call.value_of("key-name").unwrap()
        )
    } else {
        ensure_vaultfile_folder_exists();
        format!(
            "{}/.vaultfile/{}.key",
            &get_home_directory(),
            &get_username()
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
    let private_key_path = format!(
        "{}/{}.key",
        get_default_vaultfile_folder(),
        cli_call.value_of("private-key-name").unwrap()
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
    let mut vaultfile = match Vaultfile::load_from_file(&vaultfile_path) {
        Ok(vault) => vault,
        Err(error) => match error.kind {
            VaultfileErrorKind::VaultfileNotFound => Vaultfile::new(),
            _ => panic!("Bad Vaultfile!"),
        },
    };
    if !cli_call.is_present("overwrite-yes") {
        if vaultfile.keys.contains_key(key_name) {
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

fn main() {
    let username = get_username();
    let cli_call = App::new("vaultfile")
        .version("0.1.0")
        .author("Daniel Gray")
        .about("A basic shared secret/credential manager")
        .subcommand(
            SubCommand::with_name("generate-key")
                .about("Generate a new private key")
                .arg(
                    Arg::with_name("key-name")
                        .long("key-name")
                        .takes_value(true)
                        .conflicts_with("key-path")
                        .help(
                            "Name of the keyfile to generate under ~/.vaultfile (your username will be used by default)",
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
    }
}
