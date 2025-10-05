use std::{collections::HashMap, fs, path::PathBuf};

use anyhow::Result;
use object::{read::pe::ImageOptionalHeader, Object, ObjectSection, ObjectSymbol};
use iced_x86::{Decoder, DecoderOptions, Instruction, OpKind, Register};

use crate::{find_pattern_simd, is_executable, memory::get_module_base_from_pointer, };

#[cfg(target_os = "windows")]
use std::ffi::CString;
#[cfg(target_os = "windows")]
use std::os::raw::c_void;

#[cfg(target_os = "linux")]
use std::io::{BufRead, BufReader};

#[cfg(target_os = "windows")]
unsafe extern "system" {
    fn GetModuleHandleA(lpModuleName: *const u8) -> *mut c_void;
} 

pub struct S2BinLib {
    game_path: PathBuf,
    game_type: String,
    os: String,
    binaries: HashMap<String, Vec<u8>>,
    manual_base_addresses: HashMap<String, u64>,
    /// Cached cross-references: binary_name -> (target_va -> Vec<xref_va>)
    xrefs_cache: HashMap<String, HashMap<u64, Vec<u64>>>
}


fn read_int32(data: &[u8], offset: u64) -> u32 {
  let mut value = 0;
  for i in 0..4 {
    value |= (data[offset as usize + i as usize] as u32) << (i * 8);
  }
  value
}

fn read_int64(data: &[u8], offset: u64) -> i64 {
  let mut value = 0i64;
  for i in 0..8 {
    value |= (data[offset as usize + i as usize] as i64) << (i * 8);
  }
  value
}

impl S2BinLib {
    
    fn get_os_name(&self) -> String {
      match self.os.as_str()  {
        "windows" => "win64".to_string(),
        _ => "linuxsteamrt64".to_string(),
      }
    }

    fn get_os_lib_name(&self, lib_name: &str) -> String {
        match self.os.as_str() {
            "windows" => format!("{}.dll", lib_name),
            _ => format!("lib{}.so", lib_name),
        }
    }

    pub fn get_module_base_address(&self, lib_name: &str) -> Result<u64> {
        if let Some(&base_address) = self.manual_base_addresses.get(lib_name) {
            return Ok(base_address);
        }

        let module_name = self.get_os_lib_name(lib_name);
        match self.os.as_str() {
            "windows" => self.get_module_base_address_windows(&module_name),
            _ => self.get_module_base_address_linux(&module_name),
        }
    }

    #[cfg(target_os = "windows")]
    fn get_module_base_address_windows(&self, module_name: &str) -> Result<u64> {
        let c_module_name = CString::new(module_name)?;
        unsafe {
            let handle = GetModuleHandleA(c_module_name.as_ptr() as *const u8);
            if handle.is_null() {
                return Err(anyhow::anyhow!("Module '{}' not found or not loaded", module_name));
            }
            Ok(handle as u64)
        }
    }

    #[cfg(not(target_os = "windows"))]
    fn get_module_base_address_windows(&self, _module_name: &str) -> Result<u64> {
        Err(anyhow::anyhow!("Windows module loading not supported on this platform"))
    }

    #[cfg(target_os = "linux")]
    fn get_module_base_address_linux(&self, module_name: &str) -> Result<u64> {
        let maps_file = fs::File::open("/proc/self/maps")?;
        let reader = BufReader::new(maps_file);

        for line in reader.lines() {
            let line = line?;
            if line.contains(module_name) {
                // Parse the line format: "address_start-address_end perms offset dev inode pathname"
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(addr_range) = parts.first() {
                    if let Some(start_addr) = addr_range.split('-').next() {
                        return u64::from_str_radix(start_addr, 16)
                            .map_err(|e| anyhow::anyhow!("Failed to parse address: {}", e));
                    }
                }
            }
        }

        Err(anyhow::anyhow!("Module '{}' not found in process memory", module_name))
    }

    #[cfg(not(target_os = "linux"))]
    fn get_module_base_address_linux(&self, _module_name: &str) -> Result<u64> {
        Err(anyhow::anyhow!("Linux module loading not supported on this platform"))
    }

    fn decorate_rtti_type_descriptor_name(&self, name: &str) -> String {
      match self.os.as_str() {
        "windows" => format!(".?AV{}@@", name),
        _ => format!("{}{}", name.len(), name),
      }
    }
    pub fn new(game_path: &str, game_type: &str, os: &str) -> Self {
        Self { 
          game_path: PathBuf::from(game_path),
          game_type: game_type.to_string(),
          os: os.to_string(),
          binaries: HashMap::new(),
          manual_base_addresses: HashMap::new(),
          xrefs_cache: HashMap::new()
        }
    }

    /// Manually set the base address for a module from a pointer
    /// 
    /// This allows overriding the automatic base address detection.
    /// Useful when the module is loaded in a non-standard way or
    /// when you need to force a specific base address.
    /// 
    /// # Arguments
    /// * `lib_name` - The library name without extension (e.g., "server", "engine2")
    /// * `pointer` - The pointer from the module
    /// 
    /// # Example
    /// ```no_run
    /// let mut s2binlib = S2BinLib::new("path", "game", "windows");
    /// s2binlib.set_module_base_from_pointer("server", 0x140000000);
    /// ```
    pub fn set_module_base_from_pointer(&mut self, lib_name: &str, pointer: u64) {
        self.manual_base_addresses.insert(lib_name.to_string(), get_module_base_from_pointer(pointer));
    }

    /// Clear manually set base address for a module
    /// 
    /// After calling this, the module will use automatic base address detection again.
    /// 
    /// # Arguments
    /// * `lib_name` - The library name without extension (e.g., "server", "engine2")
    pub fn clear_module_base_address(&mut self, lib_name: &str) {
        self.manual_base_addresses.remove(lib_name);
    }


    pub fn get_binary_path(&self, binary_name: &str) -> String {
        match binary_name {
            "server" | "client" | "matchmaking" | "host" => self.game_path
              .join(self.game_type.clone())
              .join("bin")
              .join(self.get_os_name())
              .join(self.get_os_lib_name(binary_name))
              .to_string_lossy().to_string(),
            _ => self.game_path
              .join("bin")
              .join(self.get_os_name())
              .join(self.get_os_lib_name(binary_name))
              .to_string_lossy().to_string(),
        }
    }

    pub fn is_binary_loaded(&self, binary_name: &str) -> bool {
        self.binaries.contains_key(binary_name)
    }

    pub fn load_binary(&mut self, binary_name: &str) {
        let binary_path = self.get_binary_path(binary_name);
        let binary_data = fs::read(binary_path.clone());
        if let Ok(binary_data) = binary_data {
          self.binaries.insert(binary_name.to_string(), binary_data);
        } else {
          println!("[Warning] Binary not found: {}", binary_path.clone());
        }
    }

    pub fn get_binary(&self, binary_name: &str) -> Result<&[u8]> {
        self.binaries
            .get(binary_name)
            .map(|v| v.as_slice())
            .ok_or_else(|| anyhow::anyhow!("Binary not found."))
    }

    fn file_offset_to_va(&self, binary_name: &str, file_offset: u64) -> Result<u64> {
        let binary_data = self.get_binary(binary_name)?;
        let object = object::File::parse(binary_data)?;
        
        for section in object.sections() {
            if let Some(file_range) = section.file_range() {
                let section_file_start = file_range.0;
                let section_file_end = file_range.0 + file_range.1;


                if file_offset >= section_file_start && file_offset < section_file_end {
                    let section_va = section.address();
                    let offset_in_section = file_offset - section_file_start;
                    return Ok(section_va + offset_in_section);
                }
            }
        };
        Err(anyhow::anyhow!("File offset not found in any section."))
    }

    fn va_to_file_offset(&self, binary_name: &str, va: u64) -> Result<u64> {
        let binary_data = self.get_binary(binary_name)?;
        let object = object::File::parse(binary_data)?;

        for section in object.sections() {
          let section_va = section.address();
          let section_size = section.size();
          let section_va_end = section_va + section_size;

          if va >= section_va && va < section_va_end {
              if let Some(file_range) = section.file_range() {
                  let section_file_start = file_range.0;
                  let offset_in_section = va - section_va;
                  return Ok(section_file_start + offset_in_section);
              }
          }
        }
        Err(anyhow::anyhow!("va not found in any section."))
    }

    fn is_address_nonexecutable(&self, binary_name: &str, address: u64) -> Result<bool> {
      let binary_data = self.get_binary(binary_name)?;
      let object = object::File::parse(binary_data)?;
      for section in object.sections() {
        if let Some(file_range) = section.file_range() {
          let section_file_start = file_range.0;
          let section_file_end = file_range.0 + file_range.1;
          if address >= section_file_start && address < section_file_end {
            return Ok(!is_executable(section.flags()))
          }
        }
      };
      Err(anyhow::anyhow!("Address not found in any section."))
    }

    fn get_section_range(&self, binary_name: &str, section_name: &str) -> Result<(u64, u64)> {
      let binary_data = self.get_binary(binary_name)?;
      let object = object::File::parse(binary_data)?;
      let section = object.section_by_name(section_name).ok_or_else(|| anyhow::anyhow!("Section not found."))?;
      Ok(( section.file_range().unwrap().0, section.file_range().unwrap().1 + section.file_range().unwrap().0 ))
    }

    fn find_pattern_string(&self, binary_name: &str, string: &str) -> Result<u64> {
      let bytes = string.as_bytes().to_vec();
      // bytes.push(0); // null terminato

      self.find_pattern_bytes(binary_name, &bytes)
    }

    fn find_pattern_string_in_section(&self, binary_name: &str, section_name: &str, string: &str) -> Result<u64> {
      let bytes = string.as_bytes().to_vec();

      self.find_pattern_bytes_in_section(binary_name, section_name, &bytes)
      
    }

    fn find_pattern_bytes(&self, binary_name: &str, pattern: &[u8]) -> Result<u64> {
      let binary_data = self.get_binary(binary_name)?;
      let pattern_wildcard = vec![];
      find_pattern_simd(binary_data, pattern, &pattern_wildcard)
    }

    
    fn find_pattern_int32_in_section(&self, binary_name: &str, section_name: &str, pattern: u32) -> Result<u64> {
      let binary_data = self.get_binary(binary_name)?;
      let pattern_wildcard = vec![];

      let (start, end) = self.get_section_range(binary_name, section_name)?;
      let mut result = find_pattern_simd(&binary_data[start as usize..end as usize], &pattern.to_le_bytes(), &pattern_wildcard)?;
      if result != 0 {
        result += start;
      }
      Ok(result)
    }

    
    fn find_pattern_bytes_in_section(&self, binary_name: &str, section_name: &str, pattern: &[u8]) -> Result<u64> {
      let binary_data = self.get_binary(binary_name)?;
      let (start, end) = self.get_section_range(binary_name, section_name)?;
      let pattern_wildcard = vec![];
      let mut result = find_pattern_simd(&binary_data[start as usize..end as usize], pattern, &pattern_wildcard)?;
      if result != 0 {
        result += start;
      }
      Ok(result)
    }

    fn find_pattern_va(&self, binary_name: &str, pattern_string: &str) -> Result<u64> {
      let binary_data = self.get_binary(binary_name)?;
      let pattern = pattern_string.split(" ").map(|x| if x == "?" { 0u8 } else { u8::from_str_radix(x, 16).unwrap() }).collect::<Vec<u8>>();
      let pattern_wildcard = pattern_string.split(" ").enumerate().filter(|(_, x)| *x == "?").map(|(index, _)| index).collect::<Vec<usize>>();
      let result = find_pattern_simd(binary_data, &pattern, &pattern_wildcard)?;
      Ok(self.file_offset_to_va(binary_name, result)?)
    } 

    fn get_image_base(&self, binary_name: &str) -> Result<u64> {
      let binary_data = self.get_binary(binary_name)?;
      let object = object::File::parse(binary_data)?;
    
      match object {
          object::File::Pe64(pe) => {
              let image_base = pe.nt_headers().optional_header.image_base();
              Ok(image_base)
          }
          object::File::Pe32(pe) => {
              let image_base = pe.nt_headers().optional_header.image_base() as u64;
              Ok(image_base)
          }
          object::File::Elf64(_) | object::File::Elf32(_) => {
              Ok(0)
          }
          _ =>  Err(anyhow::anyhow!("Unsupported file format")),
      }
    }

    fn read_string(&self, binary_name: &str, file_offset: u64) -> Result<String> {
      let binary_data = self.get_binary(binary_name)?;
      let mut bytes = vec![];
      let mut file_offset = file_offset;
      while binary_data[file_offset as usize] != 0 {
        bytes.push(binary_data[file_offset as usize]);
        file_offset += 1;
      }
      Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    fn get_binary_name_by_ptr(&self, ptr: u64) -> Result<String> {
      for (binary_name, binary_data) in self.binaries.iter() {
        let base_address = self.get_module_base_address(binary_name)?;
        if ptr >= base_address && ptr < base_address + binary_data.len() as u64 {
          return Ok(binary_name.clone());
        }
      }
      Err(anyhow::anyhow!("Binary not found."))
    }

    fn find_vtable_va_windows(&self, binary_name: &str, vtable_name: &str) -> Result<u64> {
        let binary_data = self.get_binary(binary_name)?;
        let decorated_name = self.decorate_rtti_type_descriptor_name(vtable_name);

        let type_descriptor_name = self.find_pattern_string_in_section(binary_name, ".data", &decorated_name)?;

        let rtti_type_descriptor = self.file_offset_to_va(binary_name, type_descriptor_name)? - 0x10 - self.get_image_base(binary_name)?;

        let rtti_type_descriptor_ptr_pattern = rtti_type_descriptor.to_le_bytes().to_vec();

        let (_start, end) = self.get_section_range(binary_name, ".rdata")?;

        let mut reference = self.find_pattern_int32_in_section(binary_name, ".rdata", rtti_type_descriptor as u32)?;
        loop {
          if read_int32(&binary_data, reference - 0xC) == 1 && read_int32(&binary_data, reference - 0x8) == 0 {
            let reference_offset = self.file_offset_to_va(binary_name, reference - 0xC)?;
            let rtti_complete_object_locator = self.find_pattern_int32_in_section(binary_name, ".rdata", reference_offset as u32)?;
            return Ok(self.file_offset_to_va(binary_name, rtti_complete_object_locator + 8)?);
          }
          let last_reference = reference + 1;
          let result = find_pattern_simd(&binary_data[last_reference as usize..end as usize], &rtti_type_descriptor_ptr_pattern[0..4], &vec![]);
          if let Err(_) = result {
            break;
          }
          reference = result.unwrap() + last_reference as u64;
        }

        Err(anyhow::anyhow!("Vtable not found."))
    }

    fn find_vtable_va_linux(&self, binary_name: &str, vtable_name: &str) -> Result<u64> {
        let binary_data = self.get_binary(binary_name)?;
        let decorated_name = self.decorate_rtti_type_descriptor_name(vtable_name);

        let data_range = self.get_section_range(binary_name, ".rodata")?;

        let offset = data_range.0;

        let mut type_info_name = find_pattern_simd(&binary_data[offset as usize..], &decorated_name.as_bytes(), &vec![])?;
        type_info_name += offset;
        while type_info_name != 0 {

          let type_info_name_str = self.read_string(binary_name, type_info_name)?;

          if type_info_name_str == decorated_name {
            break;
          }
          let last_type_descriptor_name = type_info_name + 1;
          type_info_name = find_pattern_simd(&binary_data[last_type_descriptor_name as usize..], &decorated_name.as_bytes(), &vec![])?;
          type_info_name += last_type_descriptor_name;
        }
        
        // Find reference to type name in .data.rel.ro section (8-byte pointer)
        let type_info_name_va = self.file_offset_to_va(binary_name, type_info_name)?;
        let type_info_name_ptr_pattern = type_info_name_va.to_le_bytes();
        
        let reference_type_name = self.find_pattern_bytes_in_section(binary_name, ".data.rel.ro", &type_info_name_ptr_pattern[0..4])?;
        
        // Offset back by 0x8 to get typeinfo
        let type_info = reference_type_name - 0x8;
        let type_info_va = self.file_offset_to_va(binary_name, type_info)?;
        let type_info_ptr_pattern = type_info_va.to_le_bytes();

        // Search for references to typeinfo in .data.rel.ro and .data.rel.ro.local sections
        for section_name in &[".data.rel.ro", ".data.rel.ro.local"] {
            if let Ok((start, end)) = self.get_section_range(binary_name, section_name) {
                let mut search_offset = start;
                
                loop {
                    // Find reference to typeinfo
                    let result = find_pattern_simd(
                        &binary_data[search_offset as usize..end as usize], 
                        &type_info_ptr_pattern, 
                        &vec![]
                    );
                    
                    if result.is_err() || result.as_ref().unwrap() == &0 {
                        break;
                    }
                    
                    let reference = result.unwrap() + search_offset;
                    
                    // Check if offset to this is 0 (at -0x8 from the reference)
                    if reference >= 0x8 {
                        let offset_to_this = read_int64(binary_data, reference - 0x8);
                        if offset_to_this == 0 {
                            // Found vtable at +0x8
                            return Ok(self.file_offset_to_va(binary_name, reference + 0x8)?);
                        }
                    }
                    
                    // Continue searching after this match
                    search_offset = reference + 8;
                    if search_offset >= end {
                        break;
                    }
                }
            }
        }

        Err(anyhow::anyhow!("Vtable not found."))
    }


    

    fn mem_address_to_va(&self, binary_name: &str, address: u64) -> Result<u64> {
      let base_address = self.get_module_base_address(binary_name)?;
      let image_base = self.get_image_base(binary_name)?;
      Ok(address - base_address + image_base)
    }

     fn va_to_mem_address(&self, binary_name: &str, address: u64) -> Result<u64> {
      let base_address = self.get_module_base_address(binary_name)?;
      let image_base = self.get_image_base(binary_name)?;
      Ok(address - image_base + base_address)
    }

    pub fn find_vtable_va(&self, binary_name: &str, vtable_name: &str) -> Result<u64> {
        match self.os.as_str() {
            "windows" => self.find_vtable_va_windows(binary_name, vtable_name),
            _ => self.find_vtable_va_linux(binary_name, vtable_name),
        }
    }

    pub fn find_vtable(&self, binary_name: &str, vtable_name: &str) -> Result<u64> {
      let result = self.find_vtable_va(binary_name, vtable_name)?;
      Ok(self.va_to_mem_address(binary_name, result)?)
    }

    pub fn pattern_scan_va(&self, binary_name: &str, pattern_string: &str) -> Result<u64> {
      self.find_pattern_va(binary_name, pattern_string)
    }

    pub fn pattern_scan(&self, binary_name: &str, pattern_string: &str) -> Result<u64> {
      let result = self.find_pattern_va(binary_name, pattern_string)?;
      Ok(self.va_to_mem_address(binary_name, result)?)
    }

    
    pub fn find_export_va(&self, binary_name: &str, export_name: &str) -> Result<u64> {
      let binary_data = self.get_binary(binary_name)?;
      let object = object::File::parse(binary_data)?;

      for export in object.exports()? {
        if String::from_utf8_lossy(export.name()) == export_name {
          return Ok(export.address() as u64)
        }
      }
      Err(anyhow::anyhow!("Export not found."))
    }

    pub fn find_export(&self, binary_name: &str, export_name: &str) -> Result<u64> {
      let result = self.find_export_va(binary_name, export_name)?;
      Ok(self.mem_address_to_va(binary_name, result)?)
    }

    pub fn find_symbol_va(&self, binary_name: &str, symbol_name: &str) -> Result<u64> {
      let binary_data = self.get_binary(binary_name)?;
      let object = object::File::parse(binary_data)?;

      let symbol = object.dynamic_symbols().into_iter().find(|s| s.name() == Ok(symbol_name)).ok_or_else(|| anyhow::anyhow!("Symbol not found."))?;
      Ok(symbol.address() as u64)
    }

    pub fn find_symbol(&self, binary_name: &str, symbol_name: &str) -> Result<u64> {
      let result = self.find_symbol_va(binary_name, symbol_name)?;
      Ok(self.va_to_mem_address(binary_name, result)?)
    }

    pub fn read_by_file_offset(&self, binary_name: &str, file_offset: u64, size: usize) -> Result<Vec<u8>> {
      let binary_data: &[u8] = self.get_binary(binary_name)?;
      Ok(binary_data[file_offset as usize..file_offset as usize + size].to_vec())
    }

    pub fn read_by_va(&self, binary_name: &str, address: u64, size: usize) -> Result<Vec<u8>> {
      let file_offset = self.va_to_file_offset(binary_name, address)?;
      self.read_by_file_offset(binary_name, file_offset, size)
    }

    pub fn read_by_mem_address(&self, binary_name: &str, address: u64, size: usize) -> Result<Vec<u8>> {
      let va = self.mem_address_to_va(binary_name, address)?;
      self.read_by_va(binary_name, va, size)
    }

    pub fn find_vfunc_by_vtbname_va(&self, binary_name: &str, vtb_name: &str, vfunc_index: usize) -> Result<u64> {
      let vtb = self.find_vtable_va(binary_name, vtb_name)?;

      let vfuncptr = self.read_by_va(binary_name, vtb + vfunc_index as u64 * 8, 8)?;
      Ok(u64::from_le_bytes(vfuncptr.try_into().unwrap()))
    }

    pub fn find_vfunc_by_vtbname(&self, binary_name: &str, vtb_name: &str, vfunc_index: usize) -> Result<u64> {
      let vtb = self.find_vfunc_by_vtbname_va(binary_name, vtb_name, vfunc_index)?;
      Ok(self.va_to_mem_address(binary_name, vtb)?)
    }

    pub fn find_vfunc_by_vtbptr_va(&self, vtb_ptr: u64, vfunc_index: usize) -> Result<u64> {
      let binary_name = self.get_binary_name_by_ptr(vtb_ptr)?;
      let vtb_va = self.mem_address_to_va(&binary_name, vtb_ptr)?;
      let vfuncptr = self.read_by_va(&binary_name, vtb_va + vfunc_index as u64 * 8, 8)?;
      Ok(u64::from_le_bytes(vfuncptr.try_into().unwrap()))
    }

    pub fn find_vfunc_by_vtbptr(&self, vtb_ptr: u64, vfunc_index: usize) -> Result<u64> {
      let binary_name = self.get_binary_name_by_ptr(vtb_ptr)?;
      let vtb_va = self.mem_address_to_va(&binary_name, vtb_ptr)?;
      let vfuncptr = self.read_by_va(&binary_name, vtb_va + vfunc_index as u64 * 8, 8)?;
      let vfunc_va = u64::from_le_bytes(vfuncptr.try_into().unwrap());
      Ok(self.va_to_mem_address(&binary_name, vfunc_va)?)
    }

    pub fn find_string_va(&self, binary_name: &str, string: &str) -> Result<u64> {
      let binary_data = self.get_binary(binary_name)?;
      let string_bytes = string.as_bytes();
      let result = find_pattern_simd(binary_data, string_bytes, &vec![])?;
      Ok(self.file_offset_to_va(binary_name, result)?)
    }
    
    pub fn find_string(&self, binary_name: &str, string: &str) -> Result<u64> {
      let result = self.find_string_va(binary_name, string)?;
      Ok(self.va_to_mem_address(binary_name, result)?)
    }

    /// Dump cross-references from all executable sections
    /// 
    /// This function scans all executable sections in the binary, disassembles
    /// the instructions using iced-x86, and extracts cross-references (xrefs).
    /// The results are cached in the `xrefs_cache` HashMap.
    /// 
    /// # Arguments
    /// * `binary_name` - The name of the binary to analyze
    /// 
    /// # Returns
    /// Returns Ok(()) on success, or an error if the binary cannot be processed
    pub fn dump_xrefs(&mut self, binary_name: &str) -> Result<()> {
        let binary_data = self.get_binary(binary_name)?;
        let object = object::File::parse(binary_data)?;
        let image_base = self.get_image_base(binary_name)?;
        
        // Temporary storage for xrefs
        let mut xrefs_map: HashMap<u64, Vec<u64>> = HashMap::new();
        
        // Determine bitness for decoder
        let bitness = match object {
            object::File::Pe64(_) | object::File::Elf64(_) => 64,
            object::File::Pe32(_) | object::File::Elf32(_) => 32,
            _ => return Err(anyhow::anyhow!("Unsupported file format")),
        };

        // Iterate through all sections
        for section in object.sections() {
            // Skip non-executable sections
            if !is_executable(section.flags()) {
                continue;
            }

            // Get section data
            let section_data = match section.data() {
                Ok(data) => data,
                Err(_) => continue,
            };

            // Get section virtual address
            let section_va = section.address();

            // Create decoder
            let mut decoder = Decoder::with_ip(
                bitness,
                section_data,
                section_va,
                DecoderOptions::NONE,
            );

            let mut instruction = Instruction::default();
            
            // Decode all instructions in the section
            while decoder.can_decode() {
                decoder.decode_out(&mut instruction);
                
                // Skip invalid instructions
                if instruction.is_invalid() {
                    continue;
                }

                let instr_va = instruction.ip();

                // Analyze instruction operands for memory references
                for i in 0..instruction.op_count() {
                    let op_kind = instruction.op_kind(i);
                    
                    match op_kind {
                        // Direct memory operand (e.g., mov rax, [0x140001000])
                        OpKind::Memory => {
                            if instruction.is_ip_rel_memory_operand() {
                                // RIP-relative addressing
                                let target_va = instruction.ip_rel_memory_address();
                                xrefs_map
                                    .entry(target_va)
                                    .or_insert_with(Vec::new)
                                    .push(instr_va);
                            } else if instruction.memory_base() == Register::None 
                                   && instruction.memory_index() == Register::None {
                                // Absolute addressing
                                let displacement = instruction.memory_displacement64();
                                if displacement != 0 {
                                    xrefs_map
                                        .entry(displacement)
                                        .or_insert_with(Vec::new)
                                        .push(instr_va);
                                }
                            }
                        }
                        
                        // Near branch (call, jmp, jcc)
                        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                            let target_va = instruction.near_branch_target();
                            xrefs_map
                                .entry(target_va)
                                .or_insert_with(Vec::new)
                                .push(instr_va);
                        }
                        
                        // Immediate values that might be addresses
                        OpKind::Immediate32 | OpKind::Immediate64 => {
                            let immediate = if bitness == 64 {
                                instruction.immediate(i)
                            } else {
                                instruction.immediate(i) as u32 as u64
                            };
                            
                            // Only consider values that look like valid virtual addresses
                            // For PE files, check if it's near the image base
                            // For ELF files, check if it's in a reasonable range
                            let is_likely_address = if bitness == 64 {
                                immediate >= image_base && immediate < image_base + 0x10000000
                            } else {
                                immediate >= image_base && immediate < image_base + 0x1000000
                            };
                            
                            if is_likely_address {
                                xrefs_map
                                    .entry(immediate)
                                    .or_insert_with(Vec::new)
                                    .push(instr_va);
                            }
                        }
                        
                        _ => {}
                    }
                }
            }
        }

        // Store the collected xrefs in the cache
        self.xrefs_cache.insert(binary_name.to_string(), xrefs_map);

        Ok(())
    }

    /// Get cached cross-references for a target virtual address
    /// 
    /// Returns None if the binary hasn't been analyzed with `dump_xrefs` yet,
    /// or if there are no references to the target address.
    /// 
    /// # Arguments
    /// * `binary_name` - The name of the binary
    /// * `target_va` - The target virtual address to find references to
    /// 
    /// # Returns
    /// An optional reference to a vector of virtual addresses that reference the target
    pub fn find_xrefs_cached(&self, binary_name: &str, target_va: u64) -> Option<&Vec<u64>> {
        self.xrefs_cache
            .get(binary_name)
            .and_then(|map| map.get(&target_va))
    }

    pub fn unload_binary(&mut self, binary_name: &str) {
      self.binaries.remove(binary_name);
    }

    pub fn unload_all_binaries(&mut self) {
      self.binaries.clear();
    }

}