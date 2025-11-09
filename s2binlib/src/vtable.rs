use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Result};
use cpp_demangle::Symbol;
use msvc_demangler::{demangle, DemangleFlags};
use object::{BinaryFormat, Object, ObjectSection, read::pe::ImageOptionalHeader};
use serde::{Deserialize, Serialize};

use crate::{is_executable, s2binlib::S2BinLib};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VTableInfo {
    pub type_name: String,
    pub vtable_address: u64,
    pub methods: Vec<u64>,
    pub bases: Vec<BaseClassInfo>,
    pub model: VTableModel,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum VTableModel {
    Msvc {
        complete_object_locator: u64,
        offset: u32,
        constructor_displacement: u32,
        class_attributes: u32,
    },
    Itanium {
        offset_to_top: i64,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BaseClassInfo {
    pub type_name: String,
    pub details: BaseClassModel,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BaseClassModel {
    Msvc {
        attributes: u32,
        displacement: Pmd,
        num_contained_bases: u32,
    },
    Itanium {
        offset: i64,
        flags: u32,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
pub struct Pmd {
    pub mdisp: i32,
    pub pdisp: i32,
    pub vdisp: i32,
}

impl S2BinLib {
    pub fn dump_vtables(&mut self, binary_name: &str) -> Result<()>{
        let binary = self.get_binary(binary_name)?;
        let file = object::File::parse(binary)?;

        if !file.is_64() {
            return Err(anyhow!("only x64 binaries are supported"));
        }

        let image_base = match &file {
            object::File::Pe64(pe) => pe.nt_headers().optional_header.image_base(),
            object::File::Pe32(pe) => pe.nt_headers().optional_header.image_base() as u64,
            object::File::Elf64(_) | object::File::Elf32(_) => 0,
            _ => 0,
        };

        let view = BinaryView::new(binary, &file, image_base)?;

        let vtables = match view.format {
            BinaryFormat::Pe => MsvcParser::new(&view).parse(),
            BinaryFormat::Elf => ItaniumParser::new(&view).parse(),
            _ => Err(anyhow!("unsupported binary format")),
        }?;

        self.vtables.insert(binary_name.to_string(), vtables);
        Ok(())
    }

    pub fn get_vtables(&self, binary_name: &str) -> Result<&Vec<VTableInfo>> {
        self.vtables.get(binary_name).ok_or(anyhow!("vtables not found"))
    }
}

struct BinaryView<'a> {
    sections: Vec<SectionInfo<'a>>,
    section_map: HashMap<usize, usize>,
    format: BinaryFormat,
    image_base: u64,
}

struct SectionInfo<'a> {
    index: usize,
    name: Option<String>,
    address: u64,
    data: &'a [u8],
    executable: bool,
}

impl<'a> BinaryView<'a> {
    fn new(data: &'a [u8], file: &object::File<'a>, image_base: u64) -> Result<Self> {
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

    fn section_by_index(&self, index: usize) -> Option<&SectionInfo<'a>> {
        self.section_map
            .get(&index)
            .and_then(|position| self.sections.get(*position))
    }

    fn locate_va(&self, va: u64) -> Option<(usize, u64)> {
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

    fn read_bytes(&self, va: u64, len: usize) -> Option<&'a [u8]> {
        let (section_index, offset) = self.locate_va(va)?;
        let section = self.section_by_index(section_index)?;
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(len)?;
        if end > section.data.len() {
            return None;
        }
        Some(&section.data[start..end])
    }

    fn read_u32(&self, va: u64) -> Option<u32> {
        let bytes = self.read_bytes(va, 4)?;
        Some(u32::from_le_bytes(bytes.try_into().ok()?))
    }

    fn read_i32(&self, va: u64) -> Option<i32> {
        let bytes = self.read_bytes(va, 4)?;
        Some(i32::from_le_bytes(bytes.try_into().ok()?))
    }

    fn read_i64(&self, va: u64) -> Option<i64> {
        let bytes = self.read_bytes(va, 8)?;
        Some(i64::from_le_bytes(bytes.try_into().ok()?))
    }

    fn read_pointer_va(&self, va: u64) -> Option<u64> {
        let (section_index, offset) = self.locate_va(va)?;
        self.read_pointer(section_index, offset)
    }

    fn read_pointer(&self, section_index: usize, offset: u64) -> Option<u64> {
        let section = self.section_by_index(section_index)?;
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(8)?;
        if end > section.data.len() {
            return None;
        }
        let bytes: [u8; 8] = section.data[start..end].try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    fn read_c_string(&self, va: u64) -> Option<String> {
        let (section_index, offset) = self.locate_va(va)?;
        let section = self.section_by_index(section_index)?;
        let mut cursor = usize::try_from(offset).ok()?;
        while cursor < section.data.len() {
            if section.data[cursor] == 0 {
                let slice = &section.data[usize::try_from(offset).ok()?..cursor];
                return Some(String::from_utf8_lossy(slice).into_owned());
            }
            cursor += 1;
        }
        None
    }

    fn is_executable(&self, va: u64) -> bool {
        for section in &self.sections {
            if !section.executable {
                continue;
            }
            let len = section.data.len() as u64;
            if va >= section.address && va < section.address + len {
                return true;
            }
        }
        false
    }

    fn contains(&self, va: u64) -> bool {
        self.locate_va(va).is_some()
    }
}

struct MsvcParser<'a> {
    view: &'a BinaryView<'a>,
    type_cache: HashMap<u64, String>,
    hierarchy_cache: HashMap<u64, (u32, Vec<BaseClassInfo>)>,
}

impl<'a> MsvcParser<'a> {
    fn new(view: &'a BinaryView<'a>) -> Self {
        Self {
            view,
            type_cache: HashMap::new(),
            hierarchy_cache: HashMap::new(),
        }
    }

    fn parse(mut self) -> Result<Vec<VTableInfo>> {
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        for section in &self.view.sections {
            if !self.is_candidate_section(section) {
                continue;
            }

            let mut offset = 0usize;
            while offset + 8 <= section.data.len() {
                let locator_ptr =
                    u64::from_le_bytes(section.data[offset..offset + 8].try_into().unwrap());
                if locator_ptr != 0 {
                    if let Some(locator) = self.parse_locator(locator_ptr) {
                        let vtable_va = section.address + offset as u64 + 8;
                        if seen.insert(vtable_va) {
                            if let Some(info) = self.build_vtable_info(vtable_va, &locator) {
                                results.push(info);
                            }
                        }
                    }
                }
                offset += 8;
            }
        }

        results.sort_by_key(|entry| entry.vtable_address);
        Ok(results)
    }

    fn is_candidate_section(&self, section: &SectionInfo<'_>) -> bool {
        section.name.as_deref().map_or(false, |name| {
            let lower = name.to_ascii_lowercase();
            lower.contains(".rdata") || lower.contains(".data")
        })
    }

    fn parse_locator(&self, locator_ptr: u64) -> Option<CompleteObjectLocator> {

        let data = self.view.read_bytes(locator_ptr, 24)?;
        
        let signature = u32::from_le_bytes(data[0..4].try_into().ok()?);
        if signature > 1 {
            return None;
        }

        let offset = u32::from_le_bytes(data[4..8].try_into().ok()?);
        let cd_offset = u32::from_le_bytes(data[8..12].try_into().ok()?);
        let type_descriptor_rva = u32::from_le_bytes(data[12..16].try_into().ok()?);
        let class_descriptor_rva = u32::from_le_bytes(data[16..20].try_into().ok()?);

        let type_descriptor = self
            .view
            .image_base
            .checked_add(type_descriptor_rva as u64)?;
        let class_descriptor = self
            .view
            .image_base
            .checked_add(class_descriptor_rva as u64)?;

        if !self.view.contains(type_descriptor) || !self.view.contains(class_descriptor) {
            return None;
        }

        Some(CompleteObjectLocator {
            address: locator_ptr,
            offset,
            cd_offset,
            type_descriptor,
            class_descriptor,
        })
    }

    fn build_vtable_info(
        &mut self,
        vtable_va: u64,
        locator: &CompleteObjectLocator,
    ) -> Option<VTableInfo> {
        let type_name = self.get_type_name(locator.type_descriptor)?;
        let (class_attributes, mut bases) = self.get_class_hierarchy(locator.class_descriptor)?;
        if !bases.is_empty() {
            bases.remove(0);
        }

        let methods = self.collect_methods(vtable_va);

        Some(VTableInfo {
            type_name,
            vtable_address: vtable_va,
            methods,
            bases,
            model: VTableModel::Msvc {
                complete_object_locator: locator.address,
                offset: locator.offset,
                constructor_displacement: locator.cd_offset,
                class_attributes,
            },
        })
    }

    fn get_type_name(&mut self, type_descriptor: u64) -> Option<String> {
        if let Some(name) = self.type_cache.get(&type_descriptor) {
            return Some(name.clone());
        }

        let name_va = type_descriptor.checked_add(16)?;
        let raw = self.view.read_c_string(name_va)?;
        let trimmed = raw.trim_start_matches(".");
        let wrapped = format!("??_R0{}@8", trimmed);
        let demangled = demangle(&wrapped, DemangleFlags::COMPLETE)
            .map(|s| s.to_string())
            .and_then(|s| {
              let splited = s.split_once(" ").unwrap().1;
              let splited = splited.rsplit_once("::").unwrap().0;
              Ok(splited.to_string())
            })
            .unwrap_or(wrapped);

        self.type_cache.insert(type_descriptor, demangled.clone());
        Some(demangled)
    }

    fn get_class_hierarchy(
        &mut self,
        class_descriptor: u64,
    ) -> Option<(u32, Vec<BaseClassInfo>)> {
        if let Some(cached) = self.hierarchy_cache.get(&class_descriptor) {
            return Some(cached.clone());
        }

        let signature = self.view.read_u32(class_descriptor)?;
        if signature > 1 {
            return None;
        }

        let attributes = self.view.read_u32(class_descriptor + 4)?;
        let base_count = self.view.read_u32(class_descriptor + 8)?;
        let base_array_rva = self.view.read_u32(class_descriptor + 12)?;

        if base_count == 0 {
            self.hierarchy_cache
                .insert(class_descriptor, (attributes, Vec::new()));
            return Some((attributes, Vec::new()));
        }

        let base_array = self
            .view
            .image_base
            .checked_add(base_array_rva as u64)?;

        let mut bases = Vec::new();
        for index in 0..base_count {
            let entry_va = base_array + (index as u64 * 4);
            let descriptor_rva = self.view.read_u32(entry_va)?;
            let descriptor_va = self
                .view
                .image_base
                .checked_add(descriptor_rva as u64)?;
            if let Some(base) = self.parse_base_descriptor(descriptor_va) {
                bases.push(base);
            }
        }

        self.hierarchy_cache
            .insert(class_descriptor, (attributes, bases.clone()));

        Some((attributes, bases))
    }

    fn parse_base_descriptor(&mut self, addr: u64) -> Option<BaseClassInfo> {
        let type_descriptor_rva = self.view.read_u32(addr)?;
        let type_descriptor = self
            .view
            .image_base
            .checked_add(type_descriptor_rva as u64)?;

        let num_contained_bases = self.view.read_u32(addr + 4)?;
        let mdisp = self.view.read_i32(addr + 8)?;
        let pdisp = self.view.read_i32(addr + 12)?;
        let vdisp = self.view.read_i32(addr + 16)?;
        let attributes = self.view.read_u32(addr + 20)?;

        let type_name = self.get_type_name(type_descriptor)?;

        Some(BaseClassInfo {
            type_name,
            details: BaseClassModel::Msvc {
                attributes,
                displacement: Pmd { mdisp, pdisp, vdisp },
                num_contained_bases,
            },
        })
    }

    fn collect_methods(&self, mut vtable_va: u64) -> Vec<u64> {
        let mut methods = Vec::new();
        for _ in 0..1024 {
            let Some(method) = self.view.read_pointer_va(vtable_va) else {
                break;
            };
            if method == 0 || !self.view.is_executable(method) {
                break;
            }
            methods.push(method);
            vtable_va += 8;
        }
        methods
    }
}

#[derive(Debug)]
struct CompleteObjectLocator {
    address: u64,
    offset: u32,
    cd_offset: u32,
    type_descriptor: u64,
    class_descriptor: u64,
}

struct ItaniumParser<'a> {
    view: &'a BinaryView<'a>,
    type_cache: HashMap<u64, TypeInfoData>,
    visiting: HashSet<u64>,
}

#[derive(Clone)]
struct TypeInfoData {
    name: String,
    bases: Vec<BaseClassInfo>,
}

impl<'a> ItaniumParser<'a> {
    fn new(view: &'a BinaryView<'a>) -> Self {
        Self {
            view,
            type_cache: HashMap::new(),
            visiting: HashSet::new(),
        }
    }

    fn parse(mut self) -> Result<Vec<VTableInfo>> {
        let mut results = Vec::new();
        let mut seen = HashSet::new();

        for section in &self.view.sections {
            if !self.is_candidate_section(section) {
                continue;
            }

            let mut offset = 0usize;
            while offset + 24 <= section.data.len() {
                let typeinfo_ptr =
                    u64::from_le_bytes(section.data[offset + 8..offset + 16].try_into().unwrap());
                if typeinfo_ptr == 0 || !self.view.contains(typeinfo_ptr) {
                    offset += 8;
                    continue;
                }

                if self.resolve_typeinfo(typeinfo_ptr).is_none() {
                    offset += 8;
                    continue;
                }

                let first_method = if offset + 24 <= section.data.len() {
                    u64::from_le_bytes(section.data[offset + 16..offset + 24].try_into().unwrap())
                } else {
                    0
                };
                if first_method != 0 && !self.view.is_executable(first_method) {
                    offset += 8;
                    continue;
                }

                let vtable_va = section.address + offset as u64 + 16;
                if !seen.insert(vtable_va) {
                    offset += 8;
                    continue;
                }

                let offset_to_top =
                    i64::from_le_bytes(section.data[offset..offset + 8].try_into().unwrap());

                if let Some(info) = self.build_vtable_info(vtable_va, typeinfo_ptr, offset_to_top) {
                    results.push(info);
                }

                offset += 8;
            }
        }

        results.sort_by_key(|entry| entry.vtable_address);
        Ok(results)
    }

    fn is_candidate_section(&self, section: &SectionInfo<'_>) -> bool {
        section
            .name
            .as_deref()
            .map(|name| name.contains(".data.rel.ro"))
            .unwrap_or(false)
    }

    fn build_vtable_info(
        &mut self,
        vtable_va: u64,
        typeinfo_ptr: u64,
        offset_to_top: i64,
    ) -> Option<VTableInfo> {
        let info = self.resolve_typeinfo(typeinfo_ptr)?;
        let methods = self.collect_methods(vtable_va);
        Some(VTableInfo {
            type_name: info.name,
            vtable_address: vtable_va,
            methods,
            bases: info.bases,
            model: VTableModel::Itanium { offset_to_top },
        })
    }

    fn collect_methods(&self, mut vtable_va: u64) -> Vec<u64> {
        let mut methods = Vec::new();
        for _ in 0..1024 {
            let Some(method) = self.view.read_pointer_va(vtable_va) else {
                break;
            };
            if method == 0 || !self.view.is_executable(method) {
                break;
            }
            methods.push(method);
            vtable_va += 8;
        }
        methods
    }

    fn resolve_typeinfo(&mut self, addr: u64) -> Option<TypeInfoData> {
        if let Some(cached) = self.type_cache.get(&addr) {
            return Some(cached.clone());
        }
        if !self.visiting.insert(addr) {
            return None;
        }

        let (section_index, offset) = self.view.locate_va(addr)?;
        let section = self.view.section_by_index(section_index)?;
        let offset_usize = usize::try_from(offset).ok()?;
        if offset_usize + 16 > section.data.len() {
            self.visiting.remove(&addr);
            return None;
        }

        let name_ptr = self
            .view
            .read_pointer(section_index, offset + 8)?;
        let raw_name = self.view.read_c_string(name_ptr)?;
        let demangled_name = Symbol::new(&raw_name)
            .ok()
            .and_then(|s| s.demangle(&Default::default()).ok())
            .unwrap_or(raw_name);

        let bases = self.resolve_bases(section_index, offset);

        let data = TypeInfoData {
            name: demangled_name,
            bases,
        };

        self.visiting.remove(&addr);
        self.type_cache.insert(addr, data.clone());
        Some(data)
    }

    fn resolve_bases(&mut self, section_index: usize, offset: u64) -> Vec<BaseClassInfo> {
        if let Some(candidate) = self.view.read_pointer(section_index, offset + 16) {
            if candidate != 0 && self.looks_like_typeinfo(candidate) {
                if let Some(base) = self.resolve_typeinfo(candidate) {
                    return vec![BaseClassInfo {
                        type_name: base.name,
                        details: BaseClassModel::Itanium { offset: 0, flags: 0 },
                    }];
                }
                return Vec::new();
            }
        }
        self.parse_vmi_typeinfo(section_index, offset)
    }

    fn parse_vmi_typeinfo(&mut self, section_index: usize, offset: u64) -> Vec<BaseClassInfo> {
        let section = match self.view.section_by_index(section_index) {
            Some(section) => section,
            None => return Vec::new(),
        };
        let base_va = section.address + offset;
        let base_count = self.view.read_u32(base_va + 20).unwrap_or(0);
        if base_count == 0 {
            return Vec::new();
        }

        let mut bases = Vec::new();
        let mut entry_va = base_va + 24;
        for _ in 0..base_count {
            let Some(typeinfo_ptr) = self.view.read_pointer_va(entry_va) else {
                break;
            };
            let offset_flags = self.view.read_i64(entry_va + 8).unwrap_or(0);
            let offset = offset_flags >> 8;
            let flags = (offset_flags & 0xFF) as u32;

            if let Some(info) = self.resolve_typeinfo(typeinfo_ptr) {
                bases.push(BaseClassInfo {
                    type_name: info.name,
                    details: BaseClassModel::Itanium { offset, flags },
                });
            }

            entry_va += 16;
        }

        bases
    }

    fn looks_like_typeinfo(&self, addr: u64) -> bool {
        if let Some((section_index, offset)) = self.view.locate_va(addr) {
            if let Some(name_ptr) = self.view.read_pointer(section_index, offset + 8) {
                return self.view.read_c_string(name_ptr).is_some();
            }
        }
        false
    }
}
 