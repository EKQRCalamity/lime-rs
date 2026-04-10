use crate::{
	internal::patterns::offsets::{OffsetScanner, parse_pattern},
	traits::{ProcessMemoryPatternScan, ScanTarget},
};

use super::procmem::ProcMem;

impl ProcessMemoryPatternScan for ProcMem {
	fn scan_for_pattern(&mut self, pattern: &str) -> Option<Vec<u64>> {
		self.scan_for_pattern_in(pattern, ScanTarget::HeapAndStack)
	}

	fn scan_for_pattern_in(&mut self, pattern: &str, target: ScanTarget) -> Option<Vec<u64>> {
		let pattern = parse_pattern(pattern).ok()?;
		let scanner = OffsetScanner::default();
		let mut results = Vec::new();

		let bind = self.maps.clone();
		let regions: Vec<(u64, u64)> = match target {
			ScanTarget::HeapAndStack => {
				let mut r = bind.get_heap_regions();
				r.append(&mut bind.get_stack_regions());
				r.iter().map(|r| (r.start, r.end)).collect()
			}
			ScanTarget::Anonymous => bind
				.get_anonymous_regions()
				.iter()
				.map(|r| (r.start, r.end))
				.collect(),
			ScanTarget::AnonymousNonHeapAndStack => bind
				.get_anonymous_regions()
				.iter()
				.filter(|f| match f.pathname.as_deref() {
					None => false,
					Some(x) => !x.contains("[heap]") && !x.contains("[stack"),
				})
				.map(|r| (r.start, r.end))
				.collect(),
			ScanTarget::Module(name) => bind
				.find_regions_by_name(name)
				.iter()
				.filter(|r| r.is_readable() && r.is_executable())
				.map(|r| (r.start, r.end))
				.collect(),
			ScanTarget::Range(start, end) => vec![(start, end)],
		};

		for (start, end) in regions {
			if let Ok(mut r) = scanner.scan_range_for_pattern(self, start, end, &pattern) {
				results.append(&mut r);
			}
		}

		if results.is_empty() {
			None
		} else {
			results.sort_unstable();
			Some(results)
		}
	}
}
