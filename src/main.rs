use std::hint::black_box;

use process::find::find_pids_by_proc_name_contains;
use traits::{ProcessMemoryPatternScan, ReadProcessMemory};

mod internal {
    pub mod patterns {
        pub mod offsets;
    }
}

mod process {
    pub mod find;
}

mod devmem {
    mod write;
    mod read;
}

mod procvm {
    mod read;
    mod write;
}

pub mod procmem {
    pub mod read;
    pub mod write;
    pub mod scan;
    pub mod procmem;
}

mod ptrace {
    mod read;
    mod write;
}

pub mod traits;
pub mod errors;

const BUILD_TIMESTAMP: &str = "2025-09-01-21:00:00-UNIQUE";

fn read_input(prompt: &str) -> String {
    use std::io::Write;
    let mut buffer = String::new();
    print!("{}", prompt);
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut buffer).unwrap();
    buffer.trim().to_owned()
}

fn string_to_pattern(s: &str) -> String {
    s.bytes().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
}

fn main() {
    black_box(BUILD_TIMESTAMP);
    let target = read_input("Process name: ");
    let mode = read_input("Mode (string/pattern): ");
    let input = read_input("Input: ");

    let pattern_str = match mode.to_lowercase().as_str() {
        "string" => string_to_pattern(&input),
        _ => input,
    };

    let pids = find_pids_by_proc_name_contains(&target);

    if pids.is_none() {
        panic!("Process pids could not be found!");
    }

    println!("Pattern: {}", pattern_str);

    for pid in unsafe { pids.unwrap_unchecked() } {
        println!("PID: {}", pid);
        read_input("Press enter to continue...");

        let mut procman = procmem::procmem::ProcMem::new(pid, false).unwrap();

        if procman.refresh_maps().is_err() {
            panic!("Couldn't refresh maps!");
        }

        let maps = procman.get_maps().clone();
        let mut regions = maps.get_heap_regions();
        regions.append(&mut maps.get_stack_regions());
				println!("Scanning Heap+Stack...");
        println!("Heap & stack regions:\n{}", regions.iter().map(|x|
            format!("{} <{:#x}-{:#x}> |{}|",
                x.pathname.clone().unwrap_or_else(|| "N/A".to_string()),
                x.start, x.end, x.perm)
        ).collect::<Vec<_>>().join("\n"));
				match procman.scan_for_pattern_in(&pattern_str, traits::ScanTarget::HeapAndStack) {
            Some(addresses) => {
                println!("Matches: {}", addresses.iter().map(|a| format!("{:#x}", a)).collect::<Vec<_>>().join(", "));

                for addr in &addresses {
                    if let Ok(val) = procman.read_value::<u64>(*addr) {
                        println!("{:#x}  u64: {:#x} ({})", addr, val, val);
                    }

                    let mut string_bytes = Vec::new();
                    for i in 0..256 {
                        match procman.read_value::<u8>(*addr + i) {
                            Ok(b) if b != 0 && b.is_ascii() && !b.is_ascii_control() => string_bytes.push(b),
                            _ => break,
                        }
                    }
                    if !string_bytes.is_empty() {
                        println!("{:#x}  str: \"{}\"", addr, String::from_utf8_lossy(&string_bytes));
                    }

                    print!("{:#x}  hex: ", addr);
                    for i in 0..32 {
                        match procman.read_value::<u8>(*addr + i) {
                            Ok(b) => print!("{:02x} ", b),
                            Err(_) => print!("?? "),
                        }
                    }
                    println!();
                }
            }
            None => println!("No matches found."),
        }

				println!("Scanning Anonymous...");
				println!("Anonymous regions:\n{}", maps.get_anonymous_regions().iter().map(|x|
            format!("{} <{:#x}-{:#x}> |{}|",
                x.pathname.clone().unwrap_or_else(|| "N/A".to_string()),
                x.start, x.end, x.perm)
        ).collect::<Vec<_>>().join("\n"));

        match procman.scan_for_pattern_in(&pattern_str, traits::ScanTarget::Anonymous) {
            Some(addresses) => {
                println!("Matches: {}", addresses.iter().map(|a| format!("{:#x}", a)).collect::<Vec<_>>().join(", "));

                for addr in &addresses {
                    if let Ok(val) = procman.read_value::<u64>(*addr) {
                        println!("{:#x}  u64: {:#x} ({})", addr, val, val);
                    }

                    let mut string_bytes = Vec::new();
                    for i in 0..256 {
                        match procman.read_value::<u8>(*addr + i) {
                            Ok(b) if b != 0 && b.is_ascii() && !b.is_ascii_control() => string_bytes.push(b),
                            _ => break,
                        }
                    }
                    if !string_bytes.is_empty() {
                        println!("{:#x}  str: \"{}\"", addr, String::from_utf8_lossy(&string_bytes));
                    }

                    print!("{:#x}  hex: ", addr);
                    for i in 0..32 {
                        match procman.read_value::<u8>(*addr + i) {
                            Ok(b) => print!("{:02x} ", b),
                            Err(_) => print!("?? "),
                        }
                    }
                    println!();
                }
            }
            None => println!("No matches found."),
        }
    }
}
