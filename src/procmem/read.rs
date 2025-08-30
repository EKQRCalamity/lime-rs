use std::io::{Read, Seek, SeekFrom};

use crate::{errors::RPMError, traits::{ReadProcessMemory}};

use super::procmem::ProcMem;

impl ReadProcessMemory for ProcMem {
    fn read_value<T: Copy>(&mut self, addr: u64) -> Result<T, Box<dyn crate::traits::InternalLimeError>> {
        self.maps.can_read(addr, std::mem::size_of::<T>())?;

        let mut buffer = vec![0u8; size_of::<T>()];
        self.mem_file.seek(SeekFrom::Start(addr)).map_err(
            |_e| RPMError::ReadOutOfBounds(format!("Address {}", addr))
        )?;

        self.mem_file.read_exact(&mut buffer).map_err(
            |e| RPMError::FailedToRead(format!("error: {}", e))
        )?;

        let val = unsafe { std::ptr::read_unaligned(buffer.as_ptr() as *const T) };

        return Ok(val);
    }
}
