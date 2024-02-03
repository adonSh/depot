pub enum Error {
    AnyErr(String),
    B64Err(base64::DecodeError),
    BadPassword,
    IoErr(std::io::Error),
    NeedPassword,
    NotFound,
    SqlErr(rusqlite::Error),
    Utf8Err(std::string::FromUtf8Error),
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::AnyErr(s) => write!(f, "{}", s),
            Error::B64Err(e) => e.fmt(f),
            Error::BadPassword => write!(f, "bad password"),
            Error::IoErr(e) => e.fmt(f),
            Error::NeedPassword => write!(f, "password required but not supplied"),
            Error::NotFound => write!(f, "key not found"),
            Error::SqlErr(e) => e.fmt(f),
            Error::Utf8Err(e) => e.fmt(f),
        }
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Error {
        Error::Utf8Err(e)
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Error {
        Error::B64Err(e)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Error {
        match e {
            rusqlite::Error::QueryReturnedNoRows => Error::NotFound,
            other => Error::SqlErr(other),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Error {
        Error::IoErr(e)
    }
}

impl From<aes_gcm::Error> for Error {
    fn from(_: aes_gcm::Error) -> Error {
        Error::BadPassword
    }
}

impl From<String> for Error {
    fn from(e: String) -> Error {
        Error::AnyErr(e)
    }
}

impl From<&str> for Error {
    fn from(e: &str) -> Error {
        Error::AnyErr(String::from(e))
    }
}
