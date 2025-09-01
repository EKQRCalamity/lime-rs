use std::cmp::min;

use crate::{errors::{GeneralErrors, InvalidFormat, MemAddrError}, traits::{InternalLimeError, ReadProcessMemory}};

#[derive(Debug)]
pub struct Pattern {
    bytes: Vec<u8>,
    mask: Vec<bool>,
}

impl Pattern {
    // Parse a pattern from a string
    //
    // Formats accepted: 
    // DE AD ? DE 0A ?
    // DE AD ?? DE 0A ??
    // 0xDE 0xAD 0x? 0xDE 0x0A 0x?
    // 0xDE 0xAD 0x?? 0xDE 0x0A 0x??
    pub fn from_str(pattern: &str) -> Result<Self, Box<dyn InternalLimeError>> {
        let mut bytes = Vec::new();
        let mut mask = Vec::new();

        for ol_token in pattern.split_whitespace() {
            let token = ol_token.trim();

            let token = if token.starts_with("0x") || token.starts_with("0X") {
                &token[2..]
            } else {
                token
            };

            if token == "?" || token == "??" {
                bytes.push(0);
                mask.push(false);
            }

            match token {
                "?" | "??" => {
                    bytes.push(0);
                    mask.push(false);
                }
                t => {
                    if t.len() != 2 {
                        return Err(Box::new(
                                InvalidFormat::IsNonValidPattern(ol_token.to_string())
                        ));
                    }
                    match u8::from_str_radix(t, 16) {
                        Ok(b) => {
                            bytes.push(b);
                            mask.push(true);
                        },
                        Err(e) => {
                            return Err(Box::new(
                                InvalidFormat::ContainsInvalidCharacters(format!("{}", e)
                            )));
                        }
                    }
                }
            }
        }

        Ok(Pattern{
            bytes, mask
        })
    }

    pub fn matches(&self, slice: &[u8]) -> bool {
        if slice.len() < self.bytes.len() { return false; }
        for (i, &b) in self.bytes.iter().enumerate() {
            if self.mask[i] && slice[i] != b {
                return false;
            }
        }
        true
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

pub struct OffsetScanner {
    chunk_size: usize,
}

impl OffsetScanner {
    pub fn new(chunk_size: usize) -> Self {
        Self {
            chunk_size
        }
    }

    pub fn scan_buf_for_pattern(&self, buffer: &[u8], pattern: &Pattern) -> Result<Vec<u64>, Box<dyn InternalLimeError>> {
        let mut result_addr = Vec::new();

        if pattern.len() == 0 {
            return Err(Box::new(
                GeneralErrors::PatternIsEmpty(format!("Received: \"{:?}\"", pattern))
            ));
        }

        if buffer.len() < pattern.len() {
            return Err(Box::new(
                GeneralErrors::PatternLargerThanBuffer(format!("{:?}", pattern))
            ));
        }

        for i in 0..buffer.len().saturating_sub(pattern.bytes.len()) {
            if pattern.matches(&buffer[i..i+pattern.bytes.len()]) {
                result_addr.push(i as u64);
            }
        }

        match result_addr.len() {
            0 => Err(Box::new(
                GeneralErrors::PatternNotFound(format!("{:?}", pattern))
            )),
            _ => Ok(result_addr)
        }
    }

    pub fn scan_range_for_pattern<T: ReadProcessMemory>(
        &self,
        reader: &mut T,
        start_addr: u64,
        end_addr: u64,
        pattern: &Pattern
    ) -> Result<Vec<u64>, Box<dyn InternalLimeError>> {
        let mut results = Vec::new();

        if pattern.len() == 0 {
            return Err(Box::new(
                GeneralErrors::PatternIsEmpty(format!("Received: \"{:?}\"", pattern))
            ));
        }

        if start_addr >= end_addr {
            return Err(Box::new(
                MemAddrError::AddressOutOfBounds(
                    format!("start address ({}) bigger or equal to end address ({})", start_addr, end_addr)
                )
            ))
        }

        let mut current = start_addr;

        let overlap_size = pattern.len().saturating_sub(1);

        while current < end_addr {
            let remaining = (end_addr - current) as usize;

            let read_size = min(self.chunk_size, remaining);

            if read_size < pattern.len() {
                break;
            }

            let mut buffer = Vec::new();
            for offset in 0..read_size {
                match reader.read_value::<u8>(current + offset as u64) {
                    Ok(b) => buffer.push(b),
                    Err(_) => break,
                }
            }

            if buffer.len() >= pattern.len() {
                let chunked_results = self.scan_buf_for_pattern(&buffer, pattern)?;

                for relative in &chunked_results {
                    let absolute = current + relative;
                    results.push(absolute);
                }
            }

            current += read_size as u64;
            current = current.saturating_sub(overlap_size as u64);
        }

        results.sort_unstable();
        results.dedup_by(|a, b| a == b);

        Ok(results)
    }
}

impl Default for OffsetScanner {
    fn default() -> Self {
        Self::new(1024 * 1024)
    }
}
