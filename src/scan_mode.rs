pub fn bytes_to_hex_pattern(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}

fn string_to_pattern(s: &str) -> String {
    s.bytes().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}

fn parse_integer(input: &str) -> Result<i64, String> {
    let s = input.trim();
    let (neg, s) = if let Some(rest) = s.strip_prefix('-') { (true, rest) } else { (false, s) };
    let val = if s.starts_with("0x") || s.starts_with("0X") {
        i64::from_str_radix(&s[2..], 16).map_err(|e| e.to_string())?
    } else {
        s.parse::<i64>().map_err(|e| e.to_string())?
    };
    Ok(if neg { -val } else { val })
}

fn parse_unsigned(input: &str) -> Result<u64, String> {
    let s = input.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u64>().map_err(|e| e.to_string())
    }
}

fn signed_int_to_pattern(input: &str, size: usize) -> Result<String, String> {
    let val = parse_integer(input)?;
    let bytes: Vec<u8> = match size {
        1 => (val as i8).to_le_bytes().to_vec(),
        2 => (val as i16).to_le_bytes().to_vec(),
        4 => (val as i32).to_le_bytes().to_vec(),
        8 => val.to_le_bytes().to_vec(),
        _ => return Err("Invalid size".to_string()),
    };
    Ok(bytes_to_hex_pattern(&bytes))
}

fn unsigned_int_to_pattern(input: &str, size: usize) -> Result<String, String> {
    let val = parse_unsigned(input)?;
    let bytes: Vec<u8> = match size {
        1 => (val as u8).to_le_bytes().to_vec(),
        2 => (val as u16).to_le_bytes().to_vec(),
        4 => (val as u32).to_le_bytes().to_vec(),
        8 => val.to_le_bytes().to_vec(),
        _ => return Err("Invalid size".to_string()),
    };
    Ok(bytes_to_hex_pattern(&bytes))
}

fn float32_to_pattern(input: &str) -> Result<String, String> {
    input.trim().parse::<f32>()
        .map_err(|e| e.to_string())
        .map(|f| bytes_to_hex_pattern(&f.to_le_bytes()))
}

fn float64_to_pattern(input: &str) -> Result<String, String> {
    input.trim().parse::<f64>()
        .map_err(|e| e.to_string())
        .map(|f| bytes_to_hex_pattern(&f.to_le_bytes()))
}

#[derive(Debug, Clone, Copy)]
pub enum ScanMode {
    String,
    Pattern,
    I8, I16, I32, I64,
    U8, U16, U32, U64,
    F32, F64,
}

impl ScanMode {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "string"         => Self::String,
            "i8"             => Self::I8,
            "i16"            => Self::I16,
            "i32"            => Self::I32,
            "i64"            => Self::I64,
            "u8"             => Self::U8,
            "u16"            => Self::U16,
            "u32"            => Self::U32,
            "u64"            => Self::U64,
            "f32" | "float"  => Self::F32,
            "f64" | "double" => Self::F64,
            _                => Self::Pattern,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::String  => "string",
            Self::Pattern => "pattern",
            Self::I8      => "i8",
            Self::I16     => "i16",
            Self::I32     => "i32",
            Self::I64     => "i64",
            Self::U8      => "u8",
            Self::U16     => "u16",
            Self::U32     => "u32",
            Self::U64     => "u64",
            Self::F32     => "f32",
            Self::F64     => "f64",
        }
    }

    pub fn to_pattern(self, input: &str) -> Result<String, String> {
        match self {
            Self::String  => Ok(string_to_pattern(input)),
            Self::Pattern => Ok(input.to_string()),
            Self::I8      => signed_int_to_pattern(input, 1),
            Self::I16     => signed_int_to_pattern(input, 2),
            Self::I32     => signed_int_to_pattern(input, 4),
            Self::I64     => signed_int_to_pattern(input, 8),
            Self::U8      => unsigned_int_to_pattern(input, 1),
            Self::U16     => unsigned_int_to_pattern(input, 2),
            Self::U32     => unsigned_int_to_pattern(input, 4),
            Self::U64     => unsigned_int_to_pattern(input, 8),
            Self::F32     => float32_to_pattern(input),
            Self::F64     => float64_to_pattern(input),
        }
    }
}
