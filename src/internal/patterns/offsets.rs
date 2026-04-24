#![allow(dead_code)]

use std::cmp::min;

use basic_pattern_scanner::pattern::types::Pattern;

use crate::{
	errors::{GeneralErrors, InvalidFormat, MemAddrError},
	traits::{InternalLimeError, ReadProcessMemory},
};

// Uses the default scanner, when not on nightly and without the simd_std_unstable feature flag enabled will be Scaler, otherwise will be SIMD
use basic_pattern_scanner::scanner::scan_all;

/// Strips optional `0x`/`0X` prefixes from each token, then delegates to
/// `Pattern::from_ida_str`. Accepts both `?` and `??` as wildcards.
pub fn parse_pattern(pattern: &str) -> Result<Pattern, Box<dyn InternalLimeError>> {
	let normalized: String = pattern
		.split_whitespace()
		.map(|t| {
			if t.starts_with("0x") || t.starts_with("0X") {
				&t[2..]
			} else {
				t
			}
		})
		.collect::<Vec<_>>()
		.join(" ");

	Pattern::from_ida_str(&normalized).map_err(|e| {
		Box::new(InvalidFormat::IsNonValidPattern(format!("{:?}", e))) as Box<dyn InternalLimeError>
	})
}

pub struct OffsetScanner {
	chunk_size: usize,
}

impl OffsetScanner {
	pub fn new(chunk_size: usize) -> Self {
		Self { chunk_size }
	}

	pub fn scan_buf_for_pattern(
		&self,
		buffer: &[u8],
		pattern: &Pattern,
	) -> Result<Vec<u64>, Box<dyn InternalLimeError>> {
		if pattern.bytes.is_empty() {
			return Err(Box::new(GeneralErrors::PatternIsEmpty(
				"Empty pattern".to_string(),
			)));
		}

		if buffer.len() < pattern.bytes.len() {
			return Err(Box::new(GeneralErrors::PatternLargerThanBuffer(
				"Pattern larger than buffer".to_string(),
			)));
		}

		let results: Vec<u64> = scan_all(buffer, pattern)
			.into_iter()
			.map(|m| m.offset as u64)
			.collect();

		match results.len() {
			0 => Err(Box::new(GeneralErrors::PatternNotFound(
				"No matches found".to_string(),
			))),
			_ => Ok(results),
		}
	}

	pub fn scan_range_for_pattern<T: ReadProcessMemory>(
		&self,
		reader: &mut T,
		start_addr: u64,
		end_addr: u64,
		pattern: &Pattern,
	) -> Result<Vec<u64>, Box<dyn InternalLimeError>> {
		if pattern.bytes.is_empty() {
			return Err(Box::new(GeneralErrors::PatternIsEmpty(
				"Empty pattern".to_string(),
			)));
		}

		if start_addr >= end_addr {
			return Err(Box::new(MemAddrError::AddressOutOfBounds(format!(
				"start address ({}) bigger or equal to end address ({})",
				start_addr, end_addr
			))));
		}

		let mut results = Vec::new();
		let mut current = start_addr;
		let overlap_size = pattern.bytes.len().saturating_sub(1);

		while current < end_addr {
			let remaining = (end_addr - current) as usize;
			let read_size = min(self.chunk_size, remaining);

			if read_size < pattern.bytes.len() {
				break;
			}

			let mut buffer = vec![0u8; read_size];
			let n = reader.read_bytes(current, &mut buffer).unwrap_or(0);
			buffer.truncate(n);

			if buffer.len() >= pattern.bytes.len() {
				for m in scan_all(&buffer, pattern) {
					results.push(current + m.offset as u64);
				}
			}

			current += read_size as u64;
			current = current.saturating_sub(overlap_size as u64);
		}

		results.sort_unstable();
		results.dedup_by(|a, b| a == b);

		match results.len() {
			0 => Err(Box::new(GeneralErrors::PatternNotFound(
				"No matches found".to_string(),
			))),
			_ => Ok(results),
		}
	}
}

impl Default for OffsetScanner {
	fn default() -> Self {
		Self::new(64 * 1024)
	}
}
