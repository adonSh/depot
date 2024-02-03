//! Depot is a key-value store with optional encryption.
//! Use it as a repository for reminders, trivia, or even
//! sensitive information such as passwords.

use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, KeyInit};
use base64::prelude::BASE64_STANDARD as b64;
use base64::Engine;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha1::Sha1;

pub mod error;
pub use error::Error;

pub type Result<T> = std::result::Result<T, Error>;

pub struct Depot {
    db: rusqlite::Connection,
    salt: [u8; 32],
}

impl Depot {
    /// Returns a new storage medium (sqlite3 database)
    /// or an error if initialization is unsuccessful.
    pub fn new(path: &str) -> Result<Depot> {
        let conn = rusqlite::Connection::open(path)?;
        match conn.query_row("select data from salt", (), |row| row.get(0)) {
            Ok(s) => Ok(Depot { db: conn, salt: s }),
            _ => {
                let mut d = Depot {
                    db: conn,
                    salt: [0u8; 32],
                };
                d.init()?;
                Ok(d)
            }
        }
    }

    /// Stores the specified key and value in the depot. If the key exists
    /// then the value is updated. If a password is given it will be used to
    /// encrypt the value. Returns an error if encryption or storage fails.
    pub fn stow(&self, key: &str, val: &str, password: Option<&str>) -> Result<()> {
        let (data, nonce) = match password {
            None => (String::from(val), None),
            Some(p) => match encrypt(p.as_bytes(), &self.salt, val.as_bytes()) {
                Ok((c, n)) => (b64.encode(c), Some(n)),
                Err(e) => return Err(Error::from(e)),
            },
        };

        self.db.execute(
            "insert into storage (key, val, nonce)
            values (?1, ?2, ?3)
            on conflict (key) do
            update set
                modified = (strftime('%s', 'now')),
                val = ?2,
                nonce = ?3",
            (key, data, nonce),
        )?;

        Ok(())
    }

    /// Returns the value from the depot associated with the specified key
    /// or an error if unsuccessful. A password must be supplied for
    /// encrypted values.
    pub fn fetch(&self, key: &str, password: Option<&str>) -> Result<String> {
        let (val, nonce): (String, Option<Vec<u8>>) = self.db.query_row(
            "select val, nonce
            from storage
            where key = ?",
            (key,),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;

        match nonce {
            None => Ok(val),
            Some(n) => match password {
                Some(p) => {
                    let valbytes = b64.decode(val)?;
                    let txt = decrypt(p.as_bytes(), &self.salt, &n, &valbytes)?;
                    Ok(String::from_utf8(txt)?)
                }
                None => Err(Error::NeedPassword),
            },
        }
    }

    /// Deletes the specified key from the depot.
    /// Returns an error is unsuccessful.
    pub fn drop(&self, key: &str) -> Result<()> {
        self.db
            .execute("delete from storage where key = ?1", (key,))?;
        Ok(())
    }

    /// Writes the schema to the database.
    /// Returns an error if unsuccessful.
    fn init(&mut self) -> rusqlite::Result<usize> {
        self.db.execute_batch(
            "create table if not exists storage (
                modified   int  default (strftime('%s', 'now')),
                key        text unique not null,
                val        text not null,
                nonce      blob unique
            );

            create table if not exists salt (
                data blob not null
            );",
        )?;

        rand::thread_rng().fill_bytes(&mut self.salt);
        self.db
            .execute("insert into salt (data) values (?1)", (&self.salt,))
    }
}

/// Returns the given data encrypted with a key derived from the given
/// password and the nonce with which it was encrypted
/// or an error if unsuccessful.
fn encrypt(
    password: &[u8],
    salt: &[u8],
    data: &[u8],
) -> std::result::Result<(Vec<u8>, Vec<u8>), aes_gcm::Error> {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha1>(password, salt, 4096, &mut key);

    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);
    let ciphertext = cipher.encrypt(&nonce, data)?;

    Ok((ciphertext, Vec::from(nonce.as_slice())))
}

/// Returns the given data decrypted with the key derived from the given
/// password or an error if unsuccessful.
fn decrypt(
    password: &[u8],
    salt: &[u8],
    nonce: &[u8],
    data: &[u8],
) -> std::result::Result<Vec<u8>, aes_gcm::Error> {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha1>(password, salt, 4096, &mut key);

    let cipher = Aes256Gcm::new(aes_gcm::Key::<Aes256Gcm>::from_slice(&key));

    cipher.decrypt(aes_gcm::Nonce::from_slice(nonce), data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let val = "testing123";
        let password = "testpassword";
        let mut salt = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        let (ciphertext, nonce) = encrypt(password.as_bytes(), &salt, val.as_bytes()).unwrap();
        let plaintext = decrypt(password.as_bytes(), &salt, &nonce, &ciphertext).unwrap();
        assert_eq!(&plaintext, val.as_bytes());
        assert_eq!(String::from_utf8(plaintext).unwrap(), String::from(val));
    }
}
