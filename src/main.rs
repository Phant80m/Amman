use clap::Parser;
use dialog::DialogBox;
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use nix::unistd::Uid;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Parser)]
struct Args {
    program: Option<Vec<String>>,
}

const MAX_ATTEMPTS: usize = 5;
const KEY: &str = "AMMAN_KEY";
const PATH: &str = "/usr/share/amman";

fn setup() -> (String, String) {
    let path = PathBuf::from(PATH);

    let key = std::env::var(KEY).unwrap_or_else(|_| KEY.to_string());
    let pin;

    // Check if the file exists
    if path.exists() {
        if Uid::effective().is_root() {
            dialog::Message::new("Fatal! Program run as root".to_string())
                .show()
                .expect("Could not display dialog box");
            panic!("You must run this executable without root permissions");
        }

        // Read the encrypted string directly from the file
        let encrypted_string = fs::read_to_string(&path).expect("Failed to read amman file");
        pin = encrypted_string.trim().to_string();
    } else {
        // File doesn't exist, proceed with setup logic

        // check if root
        if !Uid::effective().is_root() {
            dialog::Message::new(
                "Fatal! Program not run as root must use 'sudo -E' or similar".to_string(),
            )
            .show()
            .expect("Could not display dialog box");
            panic!("You must run this executable with root permissions");
        }
        // rest
        let password = dialog::Input::new("Enter a password to secure selected applications:")
            .title("Amman")
            .show()
            .expect("Could not display dialog box");

        // handle errors
        let password = password.expect("Failed to obtain password");

        // Encrypt the password using magic_crypt
        let mcrypt = new_magic_crypt!(key, 256);
        pin = mcrypt.encrypt_str_to_base64(password.trim());

        // Write the encrypted string to the file
        let password = fs::write(&path, pin.as_bytes());
        if let Err(e) = password {
            dialog::Message::new(format!("failed to write amman file! {}", e))
                .show()
                .expect("Could not display dialog box");
        }
        println!("Setup succeeded, rerun program to use");
        std::process::exit(0);
    }

    (pin, key.to_string())
}

fn passcode(key: &str) -> String {
    let path = PathBuf::from(PATH);
    let password = std::fs::read_to_string(path).expect("Failed to read password from amman file");

    // Decrypt the password using magic_crypt
    let mcrypt = new_magic_crypt!(key, 256);
    let decrypted_string = mcrypt.decrypt_base64_to_string(password.trim());

    if let Err(e) = &decrypted_string {
        dialog::Message::new(format!("failed to decrypt password! {}", e))
            .show()
            .expect("Could not display dialog box");
    }
    decrypted_string.unwrap_or_default()
}

fn main() {
    let args = Args::parse();

    if args.program.is_none() {
        let reason: String = if !PathBuf::from(PATH).exists() {
            "Preparing for setup".to_string()
        } else {
            eprintln!("No program specified. Use [program] --help to see usage.");
            std::process::exit(0);
        };
        println!("{}", reason);
    }

    let (_, key) = setup();
    let program_names = args.program.clone();
    let title = program_names
        .iter()
        .flat_map(|name| {
            name.iter()
                .map(|s| s.to_lowercase().replace('_', " "))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>()
        .join(", ")
        .to_string();

    while let Some(ref program_name) = program_names {
        let mut attempt_count = 0;

        loop {
            if attempt_count >= MAX_ATTEMPTS {
                println!("Too many incorrect attempts. Exiting.");
                std::process::exit(0)
            }

            let attempts_left = MAX_ATTEMPTS - attempt_count;
            let input = dialog::Input::new(&format!(
                "Enter your passcode! Attempts left: {}",
                attempts_left
            ))
            .title(&title)
            .show()
            .expect("Could not display dialog box");

            if let Some(trimmed_input) = input.map(|s| s.trim().to_string()) {
                if trimmed_input == passcode(&key) {
                    println!("Launching program: {}", title);

                    let status = Command::new(&program_name[0])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();

                    match status {
                        Ok(_) => {
                            println!("Program exited successfully");
                        }
                        Err(e) => {
                            eprintln!("Error launching program: {}", e);
                        }
                    }
                    std::process::exit(0)
                } else {
                    attempt_count += 1;
                    dialog::Message::new(&format!(
                        "Incorrect password. Attempts left: {}",
                        attempts_left
                    ))
                    .title(&title)
                    .show()
                    .ok();
                }
            } else {
                // Handle the case where the user cancels the input
                println!("User canceled input. Exiting.");
                std::process::exit(0)
            }
        }
    }
}
