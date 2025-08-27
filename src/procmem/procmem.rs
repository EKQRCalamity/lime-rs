use std::{fs::OpenOptions, io::{Seek, SeekFrom}, path::PathBuf};

use crate::{errors::MemAddrError, traits::{InternalLimeError, ReadProcessMemory}};

pub struct ProcMem {
    pub pid: i32,
    pub mem_file: std::fs::File,
}

impl ProcMem {
    pub fn new(pid: i32, write: bool) -> Result<Self, Box<dyn InternalLimeError>> {
        let path = PathBuf::from(format!("/proc/{}/mem", pid));

        let file = OpenOptions::new()
            .read(true)
            .write(write)
            .open(&path).map_err(
                |e| MemAddrError::InvalidPid(format!("{} - io error: {}", pid, e))
            )?;

        Ok(Self { pid, mem_file: file })
    }
}
