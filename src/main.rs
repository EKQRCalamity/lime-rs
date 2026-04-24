use std::{hint::black_box, time::Instant};

use process::find::find_pids_by_proc_name_contains;
use traits::ProcessMemoryPatternScan;

mod internal {
	pub mod patterns {
		pub mod offsets;
	}
}

mod process {
	pub mod find;
}

mod devmem {
	mod read;
	mod write;
}

mod procvm {
	mod read;
	mod write;
}

pub mod procmem {
	pub mod procmem;
	pub mod read;
	pub mod scan;
	pub mod write;
}

mod ptrace {
	mod read;
	mod write;
}

pub mod errors;
pub mod scan_mode;
pub mod traits;

const BUILD_TIMESTAMP: &str = "2025-09-01-21:00:00-UNIQUE";

fn read_input(prompt: &str) -> String {
	use std::io::Write;
	let mut buffer = String::new();
	print!("{}", prompt);
	std::io::stdout().flush().unwrap();
	std::io::stdin().read_line(&mut buffer).unwrap();
	buffer.trim().to_owned()
}

use scan_mode::ScanMode;
use traits::ReadProcessMemory;

const CONTEXT_BEFORE: u64 = 8;
const CONTEXT_AFTER: u64 = 24;

fn print_match_results(
	addresses: &[u64],
	procman: &mut procmem::procmem::ProcMem,
	scan_mode: ScanMode,
	n_bytes: usize,
) {
	println!("{} match(es)", addresses.len());
	for addr in addresses {
		let region = procman
			.get_maps()
			.find_region_by_addr(*addr)
			.map(|r| {
				let name = r.pathname.as_deref().unwrap_or("anon");
				format!("{} +{:#x}", name, addr - r.start)
			})
			.unwrap_or_else(|| "unknown".to_string());

		let dump_start = addr.saturating_sub(CONTEXT_BEFORE);
		let dump_len = (CONTEXT_BEFORE + n_bytes as u64 + CONTEXT_AFTER) as usize;
		let mut dump = vec![0u8; dump_len];
		let read = procman.read_bytes(dump_start, &mut dump).unwrap_or(0);

		let hex = (0..read)
			.map(|i| {
				let abs = dump_start + i as u64;
				let in_match = abs >= *addr && abs < addr + n_bytes as u64;
				let byte_str = format!("{:02x}", dump[i]);
				if in_match {
					format!("[{}]", byte_str)
				} else {
					byte_str
				}
			})
			.collect::<Vec<_>>()
			.join(" ");

		let value = match scan_mode {
			ScanMode::U8 => procman
				.read_value::<u8>(*addr)
				.map(|v| format!("{} ({:#x})", v, v))
				.unwrap_or_default(),
			ScanMode::U16 => procman
				.read_value::<u16>(*addr)
				.map(|v| format!("{} ({:#x})", v, v))
				.unwrap_or_default(),
			ScanMode::U32 => procman
				.read_value::<u32>(*addr)
				.map(|v| format!("{} ({:#x})", v, v))
				.unwrap_or_default(),
			ScanMode::U64 => procman
				.read_value::<u64>(*addr)
				.map(|v| format!("{} ({:#x})", v, v))
				.unwrap_or_default(),
			ScanMode::I8 => procman
				.read_value::<u8>(*addr)
				.map(|v| format!("{}", v as i8))
				.unwrap_or_default(),
			ScanMode::I16 => procman
				.read_value::<u16>(*addr)
				.map(|v| format!("{}", v as i16))
				.unwrap_or_default(),
			ScanMode::I32 => procman
				.read_value::<u32>(*addr)
				.map(|v| format!("{}", v as i32))
				.unwrap_or_default(),
			ScanMode::I64 => procman
				.read_value::<u64>(*addr)
				.map(|v| format!("{}", v as i64))
				.unwrap_or_default(),
			ScanMode::F32 => procman
				.read_value::<u32>(*addr)
				.map(|v| format!("{}", f32::from_bits(v)))
				.unwrap_or_default(),
			ScanMode::F64 => procman
				.read_value::<u64>(*addr)
				.map(|v| format!("{}", f64::from_bits(v)))
				.unwrap_or_default(),
			ScanMode::String => {
				let mut s = Vec::new();
				for i in 0..256u64 {
					match procman.read_value::<u8>(*addr + i) {
						Ok(b) if b != 0 && b.is_ascii() && !b.is_ascii_control() => s.push(b),
						_ => break,
					}
				}
				String::from_utf8_lossy(&s).into_owned()
			}
			ScanMode::Pattern => String::new(),
		};

		if value.is_empty() {
			println!("  {:#x}  {}  {}", addr, region, hex);
		} else {
			println!("  {:#x}  {}  {}  \"{}\"", addr, region, hex, value);
		}
	}
}

fn main() {
	black_box(BUILD_TIMESTAMP);
	let target = read_input("Process name: ");
	let mode_str = read_input("Mode (string/pattern/u8/u16/u32/u64/i8/i16/i32/i64/f32/f64): ");
	let scan_mode = ScanMode::from_str(&mode_str);
	let input = read_input("Input: ");

	let pattern_str = match scan_mode.to_pattern(&input) {
		Ok(p) => p,
		Err(e) => {
			eprintln!("Failed to parse input as {}: {}", scan_mode.name(), e);
			return;
		}
	};

	let pids = find_pids_by_proc_name_contains(&target);

	if pids.is_none() {
		panic!("Process pids could not be found!");
	}

	let n_bytes = pattern_str.split_whitespace().count();
	println!("Pattern [{}]: {}", scan_mode.name(), pattern_str);

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
		println!(
			"Heap & stack regions:\n{}",
			regions
				.iter()
				.map(|x| format!(
					"{} <{:#x}-{:#x}> |{}|",
					x.pathname.clone().unwrap_or_else(|| "N/A".to_string()),
					x.start,
					x.end,
					x.perm
				))
				.collect::<Vec<_>>()
				.join("\n")
		);
		read_input("");

		let start = Instant::now();
		match procman.scan_for_pattern_in(&pattern_str, traits::ScanTarget::HeapAndStack) {
			Some(addresses) => {
				println!("Search took: {}micros", start.elapsed().as_micros());
				print_match_results(&addresses, &mut procman, scan_mode, n_bytes);
			}
			None => println!("No matches found."),
		}

		let scan_anon = read_input("Scan anonymous regions? (y)").to_lowercase();
		if !scan_anon.is_empty() && scan_anon != "y" && scan_anon != "yes" {
			return;
		}

		let anonymous_regions = maps.get_anonymous_regions();

		if anonymous_regions.len() == regions.len() {
			if anonymous_regions.iter().all(|x| {
				x.pathname.as_ref().map_or(false, |path| {
					path.contains("[heap]") || path.contains("[stack]")
				})
			}) {
				println!("Skipping Anonymous Scan because all regions are stack/heap regions...");
				return;
			}
		}

		println!("Scanning Anonymous...");
		println!("Anonymous regions: {}", anonymous_regions.len());
		let start = Instant::now();
		match procman.scan_for_pattern_in(&pattern_str, traits::ScanTarget::Anonymous) {
			Some(addresses) => {
				println!("Search took: {}micros", start.elapsed().as_micros());
				print_match_results(&addresses, &mut procman, scan_mode, n_bytes);
			}
			None => println!("No matches found."),
		}
	}
}
