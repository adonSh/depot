#[cfg(test)]
mod tests {
    const DB_PATH: &str = "./test.db";

    #[test]
    fn test_plain() {
        let key = "plaintext";
        let data = "testing123";

        let storage = depot::Depot::new(DB_PATH).unwrap();
        assert!(storage.stow(key, data, None).is_ok());

        let val = storage.fetch(key, None).unwrap();
        assert_eq!(val, data);

        assert!(storage.drop(key).is_ok());
        assert!(storage.fetch(key, None).is_err());
    }

    #[test]
    fn test_cipher() {
        let key = "ciphertext";
        let data = "testing123";
        let password = "password";

        let storage = depot::Depot::new(DB_PATH).unwrap();
        assert!(storage.stow(key, data, Some(password)).is_ok());

        let val = storage.fetch(key, Some(password)).unwrap();
        assert_eq!(val, data);

        assert!(storage.drop(key).is_ok());
        assert!(storage.fetch(key, Some(password)).is_err());
    }

    #[test]
    fn test_bad_decrypt() {
        let key = "baddecrypt";
        let data = "testing123";
        let goodpassword = "goodpassword";
        let badpassword = "badpassword";

        let storage = depot::Depot::new(DB_PATH).unwrap();
        assert!(storage.stow(key, data, Some(goodpassword)).is_ok());

        assert!(storage.fetch(key, Some(badpassword)).is_err());
        assert!(storage.drop(key).is_ok());
    }

    #[test]
    fn test_bad_key() {
        let storage = depot::Depot::new(DB_PATH).unwrap();
        assert!(storage.fetch("badkey", None).is_err());
    }
}
