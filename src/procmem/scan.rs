use crate::{internal::patterns::offsets::{OffsetScanner, Pattern}, traits::ProcessMemoryPatternScan};

use super::procmem::ProcMem;

impl ProcessMemoryPatternScan for ProcMem {
    fn scan_for_pattern(&mut self, pattern: &str) -> Option<Vec<u64>> {
        let pattern = match Pattern::from_str(pattern) {
            Ok(p) => p,
            Err(_) => return None,
        };
        
        let scanner = OffsetScanner::default();
        let mut all_results = Vec::new();
        
        // Scan all readable regions
        let bind = self.maps.clone();
        for region in bind.get_regions() {
            if region.is_readable() {
                match scanner.scan_range_for_pattern(self, region.start, region.end, &pattern) {
                    Ok(mut region_results) => {
                        all_results.append(&mut region_results);
                    }
                    Err(_) => {
                        continue;
                    }
                }
            }
        }
        
        if all_results.is_empty() {
            None
        } else {
            // Sort results by address
            all_results.sort_unstable();
            Some(all_results)
        }
    }
}
