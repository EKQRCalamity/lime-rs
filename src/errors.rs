use crate::traits::InternalLimeError;

pub enum MemAddrError {
    AddressInvalid(String),
    AddressOutOfBounds(String),
    AddressNotReadable(String),
    InvalidPid(String),
    ParseError(String),
    NoPermission(String)
}

pub enum RPMError {
    FailedToRead(String),
    ReadOutOfBounds(String),
    BadDataType(String),
}

pub enum WPMError {
    FailedToWrite(String),
    WriteOutOfBounds(String),
    BadDataType(String),
}

pub enum InvalidFormat {
    ContainsInvalidCharacters(String),
    IsNonValidPattern(String),
}

impl InternalLimeError for WPMError {
    fn string(&self) -> String {
        match self {
            WPMError::BadDataType(e) => format!("Bad data type: {}", e),
            WPMError::WriteOutOfBounds(e) => format!("Write out of bounds: {}", e),
            WPMError::FailedToWrite(e) => format!("Failed to write: {}", e)
        }
    }
}

impl InternalLimeError for RPMError {
    fn string(&self) -> String {
        match self {
            RPMError::BadDataType(e) => format!("Bad data type: {}", e),
            RPMError::ReadOutOfBounds(e) => format!("Read out of bounds: {}", e),
            RPMError::FailedToRead(e) => format!("Failed to read: {}", e)
        }
    }
}

impl InternalLimeError for MemAddrError {
    fn string(&self) -> String {
        match self {
            MemAddrError::AddressInvalid(e) => format!("Address is invalid: {}", e),
            MemAddrError::AddressOutOfBounds(e) => format!("Address is out of bound of process memory: {}", e),
            MemAddrError::AddressNotReadable(e) => format!("Unreadable mem region: {}", e),
            MemAddrError::InvalidPid(e) => format!("Invalid pid supplied: {}", e),
            MemAddrError::ParseError(e) => format!("Error while parsing /maps: {}", e),
            MemAddrError::NoPermission(e) => format!("Wrong permissions for region: {}", e)
        }
    }
}


