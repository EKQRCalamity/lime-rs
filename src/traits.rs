use std::fmt::{Debug, Display};

use crate::errors::{MemAddrError, RPMError, WPMError};

pub trait ReadProcessMemory {
    fn read_value<T: Copy>(&mut self, addr: u64) -> Result<T, Box<dyn InternalLimeError>>;

    fn read_bytes(&mut self, addr: u64, buf: &mut [u8]) -> Result<usize, Box<dyn InternalLimeError>> {
        let mut n = 0;
        for i in 0..buf.len() {
            match self.read_value::<u8>(addr + i as u64) {
                Ok(b) => { buf[i] = b; n += 1; }
                Err(_) => break,
            }
        }
        Ok(n)
    }
}

pub trait WriteProcessMemory {
    fn write_value<T: Copy>(&mut self, addr: u64, value: &T) -> Result<(), Box<dyn InternalLimeError>>;
}

pub enum ScanTarget<'a> {
    HeapAndStack,
    Anonymous,
    Module(&'a str),
    Range(u64, u64),
}

pub trait ProcessMemoryPatternScan {
    fn scan_for_pattern(&mut self, pattern: &str) -> Option<Vec<u64>>;
    fn scan_for_pattern_in(&mut self, pattern: &str, target: ScanTarget) -> Option<Vec<u64>>;
}

pub trait InternalLimeError {
    fn string(&self) -> String;
}

impl Debug for dyn InternalLimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.string())
    }
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


