use std::{fs::OpenOptions, path::PathBuf};

use crate::{errors::MemAddrError, internal::patterns::offsets::{OffsetScanner, Pattern}, traits::InternalLimeError};

pub struct ProcMem {
    pub pid: u32,
    pub mem_file: std::fs::File,
    pub maps: ProcMemoryMaps
}

impl ProcMem {
    pub fn new(pid: u32, write: bool) -> Result<Self, Box<dyn InternalLimeError>> {
        let maps = ProcMemoryMaps::new(pid)?;
        let path = PathBuf::from(format!("/proc/{}/mem", pid));

        let file = OpenOptions::new()
            .read(true)
            .write(write)
            .open(&path).map_err(
                |e| MemAddrError::InvalidPid(format!("{} - io error: {}", pid, e))
            )?;

        Ok(Self { pid, mem_file: file, maps })
    }

    pub fn get_maps(&self) -> &ProcMemoryMaps {
        &self.maps
    }

    pub fn refresh_maps(&mut self) -> Result<(), Box<dyn InternalLimeError>> {
        self.maps = ProcMemoryMaps::new(self.pid)?;
        Ok(())
    }

    pub fn scan_region_for_pattern(
        &mut self,
        region: &ProcMemoryRegion,
        pattern: &str
    ) -> Result<Vec<u64>, Box<dyn InternalLimeError>> {
        let pattern = Pattern::from_str(pattern)?;

        let scanner = OffsetScanner::default();
        scanner.scan_range_for_pattern(
            self,
            region.start,
            region.end,
            &pattern
        )
    }

    pub fn scan_module_for_pattern(
        &mut self,
        module_name: &str,
        pattern: &str
    ) -> Result<Vec<u64>, Box<dyn InternalLimeError>> {
        let pattern = Pattern::from_str(pattern)?;

        let scanner = OffsetScanner::default();

        let mut results = Vec::new();

        let reg_bind = self.maps.clone();
        let regions = reg_bind.find_regions_by_name(module_name);
        for region in regions {
            if region.is_readable() {
                let mut region_results = scanner.scan_range_for_pattern(
                    self,
                    region.start,
                    region.end,
                    &pattern
                )?;
                results.append(&mut region_results);
            }
        }

        results.sort_unstable();
        Ok(results)
    }

    pub fn scan_heap_for_pattern(
        &mut self,
        pattern: &str
    ) -> Result<Vec<u64>, Box<dyn InternalLimeError>> {
        let pattern = Pattern::from_str(pattern)?;
        
        let scanner = OffsetScanner::default();

        let mut results = Vec::new();

        let bind = self.maps.clone();
        let heap = bind.get_heap_regions();
        for heap_region in heap {
            let mut region_results = scanner.scan_range_for_pattern(
                self,
                heap_region.start,
                heap_region.end,
                &pattern
            )?;

            results.append(&mut region_results);
        }

        results.sort_unstable();

        Ok(results)
    }
}

#[derive(Clone)]
pub struct ProcMemoryRegion {
    pub start: u64,
    pub end: u64,
    pub perm: String,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    pub pathname: Option<String>
}

impl ProcMemoryRegion {
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr <= self.end
    }

    pub fn is_readable(&self) -> bool {
        self.perm.chars().nth(0) == Some('r')
    }

    pub fn is_writeable(&self) -> bool {
        self.perm.chars().nth(1) == Some('w')
    }

    pub fn is_executable(&self) -> bool {
        self.perm.chars().nth(2) == Some('x')
    }

    pub fn size(&self) -> u64 {
        self.end - self.start
    }
}


#[derive(Clone)]
pub struct ProcMemoryMaps {
    regions: Vec<ProcMemoryRegion>
}

impl ProcMemoryMaps {
    pub fn new(pid: u32) -> Result<Self, Box<dyn InternalLimeError>> {
        let maps_path = format!("/proc/{pid}/maps");
        let content = std::fs::read_to_string(
            &maps_path
        ).map_err(
            |e| MemAddrError::InvalidPid(format!("Failed to read maps for pid {}: {}", pid, e))
        )?;

        let mut regions = Vec::new();

        for l in content.lines() {
            if let Some(reg) = Self::parse_maps_line(l)? {
                regions.push(reg);
            }
        }

        Ok(Self { regions })
    }

    fn parse_maps_line(line: &str) -> Result<Option<ProcMemoryRegion>, Box<dyn InternalLimeError>> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return Ok(None); // Skip malformed lines
        }
        
        // Parse address range
        let addr_range = parts[0];
        let addr_parts: Vec<&str> = addr_range.split('-').collect();
        if addr_parts.len() != 2 {
            return Ok(None);
        }
        
        let start = u64::from_str_radix(addr_parts[0], 16).map_err(
            |e| MemAddrError::ParseError(format!("Invalid start address: {}", e))
        )?;
        
        let end = u64::from_str_radix(addr_parts[1], 16).map_err(
            |e| MemAddrError::ParseError(format!("Invalid end address: {}", e))
        )?;
        
        let permissions = parts[1].to_string();
        
        let offset = u64::from_str_radix(parts[2], 16).map_err(
            |e| MemAddrError::ParseError(format!("Invalid offset: {}", e))
        )?;
        
        let device = parts[3].to_string();
        
        let inode = parts[4].parse::<u64>().map_err(
            |e| MemAddrError::ParseError(format!("Invalid inode: {}", e))
        )?;
        
        let pathname = if parts.len() > 5 {
            Some(parts[5..].join(" "))
        } else {
            None
        };
        
        Ok(Some(ProcMemoryRegion {
            start,
            end,
            perm: permissions,
            offset,
            dev: device,
            inode,
            pathname,
        }))
    }

    pub fn find_region_by_addr(&self, addr: u64) -> Option<&ProcMemoryRegion> {
        self.regions.iter().find(|x| x.contains(addr))
    }

    pub fn can_read(&self, addr: u64, size: usize) -> Result<(), Box<dyn InternalLimeError>> {
        let end_addr = addr.saturating_add(size as u64 - 1);

        if let Some(reg) = self.find_region_by_addr(addr) {
            if !reg.is_readable() {
                return Err(
                    Box::new(
                        MemAddrError::NoPermission(format!(
                                "region is read protected: 0x{:x}-0x{:x}",
                                reg.start,
                                reg.end,
                        ))
                    )
                );
            }

            if !reg.contains(end_addr) {
                return Err(
                    Box::new(MemAddrError::AddressOutOfBounds(
                    format!("Read from 0x{:x} (size {}) extends beyond region boundary (0x{:x}-0x{:x})", 
                           addr, size, reg.start, reg.end)                    ))
                );
            }
        } else {
            return Err(
                Box::new(MemAddrError::AddressOutOfBounds(
                    format!("0x{:x}", addr)
                ))
            );
        }
        return Ok(());
    }

    pub fn can_write(&self, addr: u64, size: usize) -> Result<(), Box<dyn InternalLimeError>> {
        let end_addr = addr.saturating_add(size as u64 - 1);

        if let Some(reg) = self.find_region_by_addr(addr) {
            if !reg.is_writeable() {
                return Err(
                    Box::new(
                        MemAddrError::NoPermission(format!(
                                "region is write protected: 0x{:x}-0x{:x}",
                                reg.start,
                                reg.end,
                        ))
                    )
                );
            }

            if !reg.contains(end_addr) {
                return Err(
                    Box::new(MemAddrError::AddressOutOfBounds(
                        format!(
                            "write from 0x{:x} (size {}) extends beyond region boundary (0x{:x}-0x{:x})",
                            addr,
                            size,
                            reg.start,
                            reg.end
                        )
                    ))
                );
            }
        } else {
            return Err(
                Box::new(MemAddrError::AddressOutOfBounds(
                    format!("0x{:x}", addr)
                ))
            );
        }
        return Ok(());
    }

    pub fn can_execute(&self, addr: u64) -> Result<(), Box<dyn InternalLimeError>> {
        if let Some(reg) = self.find_region_by_addr(addr) {
            if !reg.is_executable() {
                return Err(
                    Box::new(
                        MemAddrError::NoPermission(format!(
                                "region is execute protected: 0x{:x}-0x{:x}",
                                reg.start,
                                reg.end,
                        ))
                    )
                );
            }
        } else {
            return Err(
                Box::new(MemAddrError::AddressOutOfBounds(
                    format!("0x{:x}", addr)
                ))
            );
        }
        return Ok(());
    }

    pub fn get_regions(&self) -> &[ProcMemoryRegion] {
        &self.regions
    }

    pub fn find_regions_by_name(&self, name: &str) -> Vec<&ProcMemoryRegion> {
        self.regions.iter()
            .filter(
                |region| {
                    region.pathname.as_ref()
                        .map_or(false, |path| path.contains(name))
                }
            ).collect()
    }

    pub fn find_regions_by_name_exact(&self, name: &str) -> Vec<&ProcMemoryRegion> {
        self.regions.iter()
            .filter(
                |region| {
                    region.pathname.as_ref()
                        .map_or(false, |p| p == name)
                }
            ).collect()
    }

    pub fn find_regions_by_prefix(&self, prefix: &str) -> Vec<&ProcMemoryRegion> {
        self.regions.iter()
            .filter(
                |region| {
                    region.pathname.as_ref()
                        .map_or(false, |p| p.starts_with(prefix))
                }
            ).collect()
    }

    pub fn find_regions_by_suffix(&self, suffix: &str) -> Vec<&ProcMemoryRegion> {
        self.regions.iter()
            .filter(
                |region| {
                    region.pathname.as_ref()
                        .map_or(false, |p| p.ends_with(suffix))
                }
            ).collect()
    }

    pub fn get_heap_regions(&self) -> Vec<&ProcMemoryRegion> {
        self.find_regions_by_name_exact("[heap]")
    }

    pub fn get_stack_regions(&self) -> Vec<&ProcMemoryRegion> {
        self.find_regions_by_prefix("[stack")
    }

    pub fn get_module_base(&self, module_name: &str) -> Option<u64> {
        self.find_regions_by_name(module_name)
            .iter().filter(
                |region| {
                    region.is_executable()
                }
            ).map(|region| region.start)
            .min()
    }

    pub fn get_module_probable_load_base(&self, module_name: &str) -> Option<u64> {
        self.find_regions_by_name(module_name)
            .iter().filter(
                |region| {
                    region.is_executable()
                }
            ).map(
                |region| {
                    region.start - region.offset
                }
            ).min()
    }
}
