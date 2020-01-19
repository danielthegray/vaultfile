mod vaultfile;

use std::path::Path;
use std::process::exit;
use vaultfile::Vaultfile;
use vaultfile::VaultfileErrorKind;

extern crate clap;
use clap::{App, Arg, SubCommand};

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

fn ensure_vaultfile_folder_exists() {
    let vaultfile_folder_path = format!("{}/.vaultfile", &get_home_directory());
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

fn check_file_overwrite(file_to_check: &str, overwrite_no: bool) {
    if Path::new(&file_to_check).exists() {
        if overwrite_no {
            eprintln!("File at '{}' already exists, and no overwriting has been selected. Doing nothing...", &file_to_check);
            exit(exitcode::OK);
        }
        print!(
            "File at '{}' already exists. Overwrite (yes/y or no/n)? ",
            &file_to_check
        );
        let mut overwrite = String::new();
        match std::io::stdin().read_line(&mut overwrite) {
            Ok(_) => (),
            Err(_) => {
                eprintln!("Failed to read user response!");
                exit(exitcode::DATAERR);
            }
        }
        if overwrite.starts_with("y") {
            return;
        }
        if overwrite.starts_with("n") {
            eprintln!("File at '{}' already exists, and no overwriting has been selected. Doing nothing...", &file_to_check);
            exit(exitcode::OK);
        }
        eprintln!("You must type yes or no!");
        exit(exitcode::DATAERR);
    }
}

fn main() {
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
                        .help(
                            "Name of the keyfile to generate under ~/.vaultfile (your username will be used by default)",
                        ),
                )
                .arg(
                    Arg::with_name("key-path")
                        .long("key-path")
                        .takes_value(true)
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
                    Arg::with_name("overwrite_no")
                    .short("n")
                    .long("no")
                    .takes_value(false)
                    .help("Set this option to NOT overwrite the key file if it already exists")
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
        if cli_call.is_present("key-name") && cli_call.is_present("key-path") {
            eprintln!("You must specify either --key-name OR --key-path, not both!");
            exit(exitcode::USAGE);
        }
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
        if !cli_call.is_present("overwrite_yes") {
            check_file_overwrite(&key_path, cli_call.is_present("overwrite_no"));
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
    }
}
