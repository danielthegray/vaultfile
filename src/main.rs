mod vaultfile;

fn print_help() {
    println!("vaultfile - A basic shared secret manager");
    println!(
        "
    Vaultfile is an encrypted secret store (like KeePassXC or other password
    managers) with several access keys, instead of a single master access key.
    
    The following options exist:
    
    --new-key[=NAME]     Generate a new key to be used with Vaultfile.
                         Optionally, a name can be provided
                         (by default it will be \"vault\").
    
    "
    );
}

fn main() {
    let cli_args = std::env::args();
    vaultfile::Vaultfile::generate_new_key("test.key");
    if cli_args.len() < 2 {
        print_help();
    }
}
