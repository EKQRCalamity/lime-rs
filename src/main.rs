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
    let mut buffer: String = String::new();
    print!("{}", prompt);
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut buffer).unwrap();
    buffer.trim().to_owned()
}

fn main() {
    black_box(BUILD_TIMESTAMP);
    let target = read_input("Process name: ");
    let pattern = read_input("Pattern: ");

    let pids = find_pids_by_proc_name_contains(&target);

    if pids.is_none() {
        panic!("Process pids could not be found!");
    }

    for pid in unsafe { pids.unwrap_unchecked() } {
        println!("PID: {}", pid);
        read_input("Press enter to continue...");

        let mut procman = procmem::procmem::ProcMem::new(pid, false).unwrap();

        if procman.refresh_maps().is_err() {
            panic!("Couldn't refresh maps!");
        };

        let maps = procman.get_maps();
        let mut regions = maps.get_heap_regions();
        regions.append(&mut maps.get_stack_regions());
        println!("Found heap&stack regions: \n{}", regions.iter().map(|x| format!("Name: {} <{}-{}> |{}| Offset: {} Dev: {} INode: {}", x.pathname.clone().unwrap_or_else(|| String::from("N/A")), x.start, x.end, x.perm, x.offset, x.dev, x.inode)).collect::<Vec<String>>().join("\n"));


        println!("Searching for pattern: {}", 
            &((&pattern).as_bytes()
            .iter()
            .map(|b| format!("0x{:02x}", b)).collect::<Vec<String>>().join(" ")));

        match procman.scan_heap_for_pattern(
            &((&pattern).as_bytes()
            .iter()
            .map(|b| format!("0x{:02x}", b)).collect::<Vec<String>>().join(" "))
        ) {
            Ok(addresses) => {
                println!("Found addresses matching pattern: {}", 
                    addresses.iter().map(|addr| format!("0x{:x}", addr)).collect::<Vec<String>>().join(","));
                
                for addr in &addresses {
                    
                    match procman.read_value::<u64>(*addr) {
                        Ok(val) => println!("Address 0x{:x} as u64: 0x{:x} ({})", addr, val, val),
                        Err(e) => println!("Failed to read u64 at 0x{:x}: {}", addr, e),
                    }
                    
                    let mut string_bytes = Vec::new();
                    for i in 0..32 {
                        match procman.read_value::<u8>(*addr + i) {
                            Ok(byte) => {
                                if byte == 0 { break; } // Handle null termination
                                if byte.is_ascii() {
                                    string_bytes.push(byte);
                                } else {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    
                    if !string_bytes.is_empty() {
                        let string_val = String::from_utf8_lossy(&string_bytes);
                        println!("Address 0x{:x} as string: \"{}\"", addr, string_val);
                    }
                    
                    // Hex dump 32 bytes around the value
                    print!("Address 0x{:x} hex dump: ", addr);
                    for i in 0..32 {
                        match procman.read_value::<u8>(*addr + i) {
                            Ok(byte) => print!("{:02x} ", byte),
                            Err(_) => print!("?? "),
                        }
                    }
                    println!();
                }
            }            
            Err(_) => println!("No region found with pattern!"),
        }
    }
}
