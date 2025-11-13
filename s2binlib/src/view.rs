use std::collections::HashMap;

use anyhow::{Result, bail};
use object::{BinaryFormat, Object, ObjectSection, read::pe::ImageOptionalHeader};

use crate::{
    S2BinLib, is_executable,
    memory::{get_module_base_from_pointer, module_from_pointer, module_sections_from_slice},
    module::get_module_info,
};

mod linux {
    use super::SectionInfo;
    use object::{BinaryFormat, Object, ObjectSection};
    use std::{
        fs::{self, File},
        io::{BufRead, BufReader},
    };

    #[cfg(target_os = "linux")]
    pub(super) fn build_sections<'a>(
        data: &'a [u8],
        real_image_base: u64,
        image_base: u64,
    ) -> Option<Vec<SectionInfo<'a>>> {
        let path = module_path(real_image_base)?;
        let binary = fs::read(&path).ok()?;
        let file = object::File::parse(&*binary).ok()?;
        let mut sections = Vec::new();

        for section in file.sections() {
            let size = usize::try_from(section.size()).ok()?;
            if size == 0 {
                continue;
            }
            let address = section.address();
            let relative = address.checked_sub(image_base).unwrap_or(address);
            let real_address = real_image_base.checked_add(relative)?;
            let offset = usize::try_from(real_address.checked_sub(real_image_base)?).ok()?;
            if offset >= data.len() {
                continue;
            }
            let available = data.len() - offset;
            if available == 0 {
                continue;
            }
            let slice_size = size.min(available);
            let end = offset + slice_size;
            sections.push(SectionInfo {
                index: section.index().0 as usize,
                name: section.name().ok().map(|s| s.to_string()),
                address,
                real_address,
                data: &data[offset..end],
                executable: crate::is_executable(section.flags()),
            });
        }

        if sections.is_empty() {
            return None;
        }

        sections.sort_by_key(|entry| entry.real_address());
        Some(sections)
    }

    fn module_path(base: u64) -> Option<String> {
        let file = File::open("/proc/self/maps").ok()?;
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }
            let mut bounds = parts[0].split('-');
            let start = u64::from_str_radix(bounds.next()?, 16).ok()?;
            let end = u64::from_str_radix(bounds.next()?, 16).ok()?;
            if base < start || base >= end {
                continue;
            }
            let path = parts[5..].join(" ");
            if path.starts_with('/') {
                return Some(path);
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct SectionInfo<'a> {
    index: usize,
    name: Option<String>,
    address: u64,
    real_address: u64,
    data: &'a [u8],
    executable: bool,
}

impl<'a> SectionInfo<'a> {
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn address(&self) -> u64 {
        self.address
    }
    pub fn real_address(&self) -> u64 {
        self.real_address
    }
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    pub fn executable(&self) -> bool {
        self.executable
    }
}

pub trait LePrimitive: Sized {
    const WIDTH: usize;
    fn from_le(bytes: &[u8]) -> Option<Self>;
}

macro_rules! impl_le_primitive {
    ($($ty:ty),* $(,)?) => {
        $(impl LePrimitive for $ty {
            const WIDTH: usize = core::mem::size_of::<$ty>();
            fn from_le(bytes: &[u8]) -> Option<Self> {
                let array: [u8; core::mem::size_of::<$ty>()] = bytes.try_into().ok()?;
                Some(<$ty>::from_le_bytes(array))
            }
        })*
    };
}

impl_le_primitive!(u32, i32, i64, u64, f32, f64);

pub trait BinaryView<'a> {
    fn image_base(&self) -> u64;
    fn follow_rva(&self, rva: u32) -> Option<u64> {
        self.image_base().checked_add(rva as u64)
    }
    fn sections(&self) -> &[SectionInfo<'a>];
    fn section_by_index(&self, index: usize) -> Option<&SectionInfo<'a>>;
    fn locate_address(&self, address: u64) -> Option<(usize, u64)>;
    fn read_bytes(&'a self, address: u64, len: usize) -> Option<&'a [u8]>;
    fn read<T: LePrimitive>(&'a self, address: u64) -> Option<T> {
        let bytes = self.read_bytes(address, T::WIDTH)?;
        T::from_le(bytes)
    }
    fn read_c_string(&self, address: u64) -> Option<String> {
        let (section_index, offset) = self.locate_address(address)?;
        let section = self.section_by_index(section_index)?;
        let mut cursor = usize::try_from(offset).ok()?;
        let start = cursor;
        while cursor < section.data.len() {
            if section.data[cursor] == 0 {
                return Some(String::from_utf8_lossy(&section.data[start..cursor]).into_owned());
            }
            cursor += 1;
        }
        None
    }
    fn is_executable(&self, address: u64) -> bool {
        self.sections().iter().any(|section| {
            if !section.executable {
                return false;
            }
            let len = section.data.len() as u64;
            address >= section.address && address < section.address + len
        })
    }
    fn contains(&self, address: u64) -> bool {
        self.locate_address(address).is_some()
    }
}

#[derive(Debug)]
pub struct FileBinaryView<'a> {
    sections: Vec<SectionInfo<'a>>,
    section_map: HashMap<usize, usize>,
    image_base: u64,
}

impl<'a> FileBinaryView<'a> {
    pub fn new(data: &'a [u8], file: &object::File<'a>, image_base: u64) -> Result<Self> {
        let mut sections = Vec::new();
        let mut section_map = HashMap::new();

        for section in file.sections() {
            let Some((file_offset, size)) = section.file_range() else {
                continue;
            };
            if size == 0 {
                continue;
            }

            let start = file_offset as usize;
            let end = start + size as usize;
            if end > data.len() || start >= end {
                continue;
            }

            let index = section.index().0 as usize;
            let name = section.name().ok().map(|s| s.to_string());
            let address = section.address();
            let executable = is_executable(section.flags());

            section_map.insert(index, sections.len());
            sections.push(SectionInfo {
                index,
                name,
                address,
                real_address: address,
                data: &data[start..end],
                executable,
            });
        }

        Ok(Self {
            sections,
            section_map,
            image_base,
        })
    }
}

impl<'a> BinaryView<'a> for FileBinaryView<'a> {
    fn image_base(&self) -> u64 {
        self.image_base
    }

    fn sections(&self) -> &[SectionInfo<'a>] {
        &self.sections
    }

    fn section_by_index(&self, index: usize) -> Option<&SectionInfo<'a>> {
        self.section_map
            .get(&index)
            .and_then(|position| self.sections.get(*position))
    }

    fn locate_address(&self, va: u64) -> Option<(usize, u64)> {
        for section in &self.sections {
            let len = section.data.len() as u64;
            if len == 0 {
                continue;
            }
            if va >= section.address && va < section.address + len {
                return Some((section.index, va - section.address));
            }
        }
        None
    }

    fn read_bytes(&'a self, va: u64, len: usize) -> Option<&'a [u8]> {
        let (section_index, offset) = self.locate_address(va)?;
        let section = self.section_by_index(section_index)?;
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(len)?;
        if end > section.data.len() {
            return None;
        }
        Some(&section.data[start..end])
    }
}

#[derive(Debug)]
pub struct MemoryView<'a> {
    sections: Vec<SectionInfo<'a>>,
    image_base: u64,
    real_image_base: u64,
}

impl<'a> MemoryView<'a> {
    pub unsafe fn new(base: *const u8, len: usize, image_base: u64) -> Self {
        let data = unsafe { std::slice::from_raw_parts(base, len) };
        let real_image_base = base as usize as u64;
        let mut sections = Vec::new();

        let linux_sections: Option<Vec<SectionInfo<'a>>> = {
            #[cfg(target_os = "linux")]
            {
                linux::build_sections(data, real_image_base, image_base)
            }
            #[cfg(not(target_os = "linux"))]
            {
                None
            }
        };

        if let Some(detected_sections) = linux_sections {
            sections = detected_sections;
        }

        if sections.is_empty() {
            if let Ok(descriptors) = module_sections_from_slice(data, image_base) {
                for descriptor in descriptors {
                    let start = descriptor.offset.min(data.len());
                    let end = start.saturating_add(descriptor.size).min(data.len());
                    if start >= end {
                        continue;
                    }
                    let real_address = real_image_base + descriptor.offset as u64;
                    sections.push(SectionInfo {
                        index: descriptor.index,
                        name: descriptor.name,
                        address: descriptor.address,
                        real_address,
                        data: &data[start..end],
                        executable: descriptor.executable,
                    });
                }
            }
        }

        if sections.is_empty() {
            sections.push(SectionInfo {
                index: 0,
                name: None,
                address: image_base,
                real_address: real_image_base,
                data,
                executable: true,
            });
        } else {
            sections.sort_by_key(|section| (section.real_address, section.index));
        }

        Self {
            sections,
            image_base,
            real_image_base,
        }
    }
}

impl<'a> BinaryView<'a> for MemoryView<'a> {
    fn image_base(&self) -> u64 {
        self.image_base
    }

    fn follow_rva(&self, rva: u32) -> Option<u64> {
        self.real_image_base.checked_add(rva as u64)
    }

    fn sections(&self) -> &[SectionInfo<'a>] {
        &self.sections
    }

    fn section_by_index(&self, index: usize) -> Option<&SectionInfo<'a>> {
        self.sections.iter().find(|section| section.index == index)
    }

    fn locate_address(&self, va: u64) -> Option<(usize, u64)> {
        for section in &self.sections {
            let len = section.data.len() as u64;
            if len == 0 {
                continue;
            }
            if va >= section.real_address && va < section.real_address + len {
                return Some((section.index, va - section.real_address));
            }
            if va >= section.address && va < section.address + len {
                return Some((section.index, va - section.address));
            }
        }
        None
    }

    fn read_bytes(&'a self, va: u64, len: usize) -> Option<&'a [u8]> {
        let (section_index, offset) = self.locate_address(va)?;
        let section = self.section_by_index(section_index)?;
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(len)?;
        if end > section.data.len() {
            return None;
        }
        Some(&section.data[start..end])
    }

    fn is_executable(&self, address: u64) -> bool {
        self.sections.iter().any(|section| {
            if !section.executable {
                return false;
            }
            let len = section.data.len() as u64;
            (address >= section.real_address && address < section.real_address + len)
                || (address >= section.address && address < section.address + len)
        })
    }
}

impl<'a> S2BinLib<'a> {
    pub fn get_file_binary_view(&self, binary_name: &str) -> Result<FileBinaryView<'_>> {
        let binary = self.get_binary(binary_name)?;
        let file = object::File::parse(binary)?;

        let image_base = match &file {
            object::File::Pe64(pe) => pe.nt_headers().optional_header.image_base(),
            object::File::Pe32(pe) => pe.nt_headers().optional_header.image_base() as u64,
            object::File::Elf64(_) | object::File::Elf32(_) => 0,
            _ => 0,
        };
        FileBinaryView::new(binary, &file, image_base)
    }

    pub fn get_memory_view_from_ptr(&self, ptr: u64) -> Result<MemoryView<'_>> {
        let module_base = self.module_from_pointer(ptr)?;

        let module_info = get_module_info(module_base)?;
        let memory_view = unsafe {
            MemoryView::new(
                module_info.base_address as *const u8,
                module_info.size,
                module_base,
            )
        };
        Ok(memory_view)
    }
}
