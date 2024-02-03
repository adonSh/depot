use std::env;
use std::fs;
use std::io;
use std::io::Write;
use std::path::Path;

use termion::input::TermRead;

use depot::{Depot, Error, Result};

const ACT_STOW: &str = "stow";
const ACT_FETCH: &str = "fetch";
const ACT_DROP: &str = "drop";
const ACT_HELP: &str = "help";

const ENV_PATH: &str = "DEPOT_PATH";
const ENV_PASS: &str = "DEPOT_PASS";

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let (action, key, secret, newline) = parse_args(&args[1..])?;
    let db_path = choose_path()?;
    let storage = Depot::new(&db_path)?;

    match action {
        ACT_STOW => {
            let val = get_val(secret)?;
            let password = if secret { Some(get_password()?) } else { None };
            storage.stow(key, &val, password.as_deref())
        }
        ACT_FETCH => {
            let val = match storage.fetch(key, None) {
                Ok(v) => v,
                Err(Error::NeedPassword) => storage.fetch(key, Some(&get_password()?))?,
                Err(e) => return Err(e),
            };

            print!("{}{}", val, if newline { "\n" } else { "" });
            Ok(())
        }
        ACT_DROP => storage.drop(key),
        ACT_HELP => Ok(println!("{}", usage())),
        act => Err(Error::from(format!("unrecognized action: {}", act))),
    }
}

/// Returns the password from either an environment variable or console input
/// or an error if unsuccessful.
fn get_password() -> Result<String> {
    match env::var(ENV_PASS) {
        Ok(p) => Ok(p),
        _ => {
            let mut tty_in = fs::File::open("/dev/tty")?;
            let mut tty_out = fs::File::create("/dev/tty")?;
            tty_out.write_all("PASSWORD: ".as_bytes())?;

            let password = tty_in.read_passwd(&mut tty_out)?;
            tty_out.write_all("\n".as_bytes())?;

            match password {
                Some(p) => Ok(String::from(p.trim())),
                None => Err(Error::BadPassword),
            }
        }
    }
}

/// Returns the value read from stdin or an error if unsuccessful
fn get_val(secret: bool) -> Result<String> {
    let val = if secret && termion::is_tty(&io::stdin()) {
        match io::stdin().read_passwd(&mut io::stdout())? {
            Some(v) => v,
            None => return Err(Error::from("value must be a non-empty string")),
        }
    } else {
        let mut v = String::new();
        io::stdin().read_line(&mut v)?;
        v
    };

    match val.trim() {
        "" => Err(Error::from("value must be a non-empty string")),
        v => Ok(String::from(v)),
    }
}

/// Returns the key, options, and action to perform specified in
/// the command-line arguments or an error if parsing is unsuccessful.
fn parse_args(args: &[String]) -> Result<(&str, &str, bool, bool)> {
    let mut action = "";
    let mut key = "";
    let mut secret = false;
    let mut newline = true;

    for a in args.iter() {
        if a == "-h" || a == "--help" || a == "-?" {
            return Ok((ACT_HELP, key, secret, newline));
        }

        if a.starts_with('-') {
            secret = secret || a.contains('s');
            newline = newline && !a.contains('n');
        } else if action.is_empty() {
            if a == ACT_HELP {
                return Ok((ACT_HELP, key, secret, newline));
            }
            action = a;
        } else if key.is_empty() {
            key = a;
        } else {
            return Err(Error::from("one key at a time"));
        }
    }

    if action.is_empty() {
        Err(Error::from("no action specified"))
    } else if key.is_empty() {
        Err(Error::from("no key specified"))
    } else {
        Ok((action, key, secret, newline))
    }
}

/// Returns the location of the database in the filesystem
/// depending on the environment or an error if a path cannot be determined.
fn choose_path() -> Result<String> {
    match env::var(ENV_PATH) {
        Ok(p) => Ok(p),
        _ => {
            let path = match env::var("XDG_CONFIG_HOME") {
                Ok(p) => Path::new(&p).join("depot"),
                _ => match env::var("HOME") {
                    Ok(p) => Path::new(&p).join(".depot"),
                    _ => Path::new(".").join(".depot"),
                },
            };

            fs::create_dir_all(&path)?;
            match path.join("depot.db").to_str() {
                None => Err(Error::from("config path has bad characters")),
                Some(p) => Ok(String::from(p)),
            }
        }
    }
}

/// Returns the help message
fn usage() -> String {
    [
        "Usage: depot [-nsh?] <action> <key>",
        "",
        "Actions:",
        "    stow        Read a value from stdin and associate it with the given key",
        "    fetch       Print the value associated with the given key to stdout",
        "    drop        Remove the given key from the depot",
        "",
        "Options:",
        "    -n          No newline character will be printed after fetching a value",
        "    -s          The provided value is secret and will be encrypted",
        "    -h, -?      Print this help message and exit",
        "",
        "Environment Variables:",
        "    DEPOT_PATH  Specifies a non-standard path to the depot's database",
        "                (Defaults to $XDG_CONFIG_HOME/depot/depot.db)",
        "    DEPOT_PASS  Specifies the password to be used to encrypt/decrypt values",
        "                (Be careful with this! It is certainly less secure!)",
    ]
    .join("\n")
}
