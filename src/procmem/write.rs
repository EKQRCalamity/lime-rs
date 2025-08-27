use std::io::{Seek, SeekFrom, Write};

use crate::{errors::WPMError, traits::WriteProcessMemory};

use super::procmem::ProcMem;

impl WriteProcessMemory for ProcMem {
    fn write_value<T: Copy>(&mut self, addr: u64, value: &T) -> Result<(), Box<dyn crate::traits::InternalLimeError>> {
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (value as *const T) as *const u8,
                size_of::<T>()
            )
        };

        self.mem_file.seek(SeekFrom::Start(addr)).map_err(
            |e| WPMError::WriteOutOfBounds(format!("error: {}", e))
        )?;
        self.mem_file.write_all(bytes).map_err(
            |e| WPMError::FailedToWrite(format!("error: {}", e))
        )?;

        return Ok(());
    }
}
