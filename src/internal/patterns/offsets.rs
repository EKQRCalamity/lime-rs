use crate::{errors::InvalidFormat, procmem::procmem::ProcMem};

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
    pub fn from_str(pattern: &str) -> Result<Self, InvalidFormat> {
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
                        return Err(InvalidFormat::IsNonValidPattern(ol_token.to_string()));
                    }
                    match u8::from_str_radix(t, 16) {
                        Ok(b) => {
                            bytes.push(b);
                            mask.push(true);
                        },
                        Err(e) => {
                            return Err(InvalidFormat::ContainsInvalidCharacters(format!("{}", e)));
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
}

pub struct ProcMemOffsetScanner {
    pub results: usize,
    pub result_addr: Vec<usize>
}

impl ProcMemOffsetScanner {
    pub fn scan_buf_for_pattern(&mut self, buffer: &[u8], pattern: Pattern) {
        self.results = 0;
        self.result_addr = Vec::new();

        for i in 0..buffer.len().saturating_sub(pattern.bytes.len()) {
            if pattern.matches(&buffer[i..i+pattern.bytes.len()]) {
                self.results += 1;
                self.result_addr.push(i);
            }
        }
    }

    pub fn scan_proc_for_pattern(&mut self, procmem: ProcMem, pattern: Pattern) {

    }
}
