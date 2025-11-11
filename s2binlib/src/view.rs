use std::collections::HashMap;

use anyhow::Result;
use object::{BinaryFormat, Object, ObjectSection};

use crate::{is_executable, memory::module_sections_from_slice};

#[derive(Debug)]
pub struct SectionInfo<'a> {
    index: usize,
    name: Option<String>,
    address: u64,
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
    fn format(&self) -> BinaryFormat;
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
    format: BinaryFormat,
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
                data: &data[start..end],
                executable,
            });
        }

        Ok(Self {
            sections,
            section_map,
            format: file.format(),
            image_base,
        })
    }
}

impl<'a> BinaryView<'a> for FileBinaryView<'a> {
    fn format(&self) -> BinaryFormat {
        self.format
    }

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
    format: BinaryFormat,
    image_base: u64,
}

impl<'a> MemoryView<'a> {
    pub unsafe fn new(base: *const u8, len: usize, image_base: u64, format: BinaryFormat) -> Self {
        let data = unsafe { std::slice::from_raw_parts(base, len) };
        let mut sections = Vec::new();

        if let Ok(descriptors) = module_sections_from_slice(data, image_base, format) {
            for descriptor in descriptors {
                let start = descriptor.offset.min(data.len());
                let end = start.saturating_add(descriptor.size).min(data.len());
                if start >= end {
                    continue;
                }
                sections.push(SectionInfo {
                    index: descriptor.index,
                    name: descriptor.name,
                    address: descriptor.address,
                    data: &data[start..end],
                    executable: descriptor.executable,
                });
            }
        }

        if sections.is_empty() {
            sections.push(SectionInfo {
                index: 0,
                name: None,
                address: image_base,
                data,
                executable: true,
            });
        }

        Self {
            sections,
            format,
            image_base,
        }
    }
}

impl<'a> BinaryView<'a> for MemoryView<'a> {
    fn format(&self) -> BinaryFormat {
        self.format
    }

    fn image_base(&self) -> u64 {
        self.image_base
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