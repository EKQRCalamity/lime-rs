use std::fmt::Display;

use crate::errors::{MemAddrError, RPMError, WPMError};

pub trait ReadProcessMemory {
    fn read_value<T: Copy>(&mut self, addr: u64) -> Result<T, Box<dyn InternalLimeError>>;
}

pub trait WriteProcessMemory {
    fn write_value<T: Copy>(&mut self, addr: u64, value: &T) -> Result<(), Box<dyn InternalLimeError>>;
}

pub trait ProcessMemoryPatternScan {
    fn scan_for_pattern(&mut self, pattern: &str) -> Option<Vec<u64>>;
}

pub trait InternalLimeError {
    fn string(&self) -> String;
}

impl Display for dyn InternalLimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.string())
    }
}

impl From<WPMError> for Box<dyn InternalLimeError> {
    fn from(value: WPMError) -> Self {
        Box::new(value)
    }
}

impl From<RPMError> for Box<dyn InternalLimeError> {
    fn from(value: RPMError) -> Self {
        Box::new(value)
    }
}

impl From<MemAddrError> for Box<dyn InternalLimeError> {
    fn from(value: MemAddrError) -> Self {
        Box::new(value)
    }
}


