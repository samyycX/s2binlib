use std::ffi::CString;

#[derive(Debug)]
pub struct ModuleInfo {
    pub base_address: usize,
    pub size: usize,
}

#[derive(Debug)]
pub enum ModuleError {
    NotFound,
    InvalidName,
    SystemError(String),
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ModuleError::NotFound => write!(f, "Module not found"),
            ModuleError::InvalidName => write!(f, "Invalid module name"),
            ModuleError::SystemError(msg) => write!(f, "System error: {}", msg),
        }
    }
}

impl std::error::Error for ModuleError {}

pub fn get_module_info(module_name: &str) -> Result<ModuleInfo, ModuleError> {
    #[cfg(target_os = "windows")]
    {
        get_module_info_windows(module_name)
    }
    
    #[cfg(target_os = "linux")]
    {
        get_module_info_linux(module_name)
    }
    
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err(ModuleError::SystemError("Unsupported platform".to_string()))
    }
}

#[cfg(target_os = "windows")]
fn get_module_info_windows(module_name: &str) -> Result<ModuleInfo, ModuleError> {
    use std::mem;
    use winapi::shared::minwindef::{HMODULE, FALSE};
    use winapi::um::psapi::{GetModuleInformation, MODULEINFO};
    use winapi::um::libloaderapi::GetModuleHandleA;
    use winapi::um::processthreadsapi::GetCurrentProcess;
    
    let c_name = CString::new(module_name)
        .map_err(|_| ModuleError::InvalidName)?;
    
    unsafe {
        let h_module: HMODULE = GetModuleHandleA(c_name.as_ptr());
        
        if h_module.is_null() {
            return Err(ModuleError::NotFound);
        }
        
        let mut mod_info: MODULEINFO = mem::zeroed();
        let result = GetModuleInformation(
            GetCurrentProcess(),
            h_module,
            &mut mod_info,
            mem::size_of::<MODULEINFO>() as u32,
        );
        
        if result == FALSE {
            return Err(ModuleError::SystemError("GetModuleInformation failed".to_string()));
        }
        
        Ok(ModuleInfo {
            base_address: mod_info.lpBaseOfDll as usize,
            size: mod_info.SizeOfImage as usize,
        })
    }
}

#[cfg(target_os = "linux")]
fn get_module_info_linux(module_name: &str) -> Result<ModuleInfo, ModuleError> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    
    let maps_file = File::open("/proc/self/maps")
        .map_err(|e| ModuleError::SystemError(format!("Cannot open /proc/self/maps: {}", e)))?;
    
    let reader = BufReader::new(maps_file);
    let mut base_address: Option<usize> = None;
    let mut end_address: Option<usize> = None;
    
    for line in reader.lines() {
        let line = line.map_err(|e| ModuleError::SystemError(format!("Read error: {}", e)))?;
        
        if line.contains(module_name) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            
            let addr_range: Vec<&str> = parts[0].split('-').collect();
            if addr_range.len() != 2 {
                continue;
            }
            
            let start = usize::from_str_radix(addr_range[0], 16)
                .map_err(|_| ModuleError::SystemError("Invalid address format".to_string()))?;
            let end = usize::from_str_radix(addr_range[1], 16)
                .map_err(|_| ModuleError::SystemError("Invalid address format".to_string()))?;
            
            if base_address.is_none() {
                base_address = Some(start);
            }
            
            end_address = Some(end);
        }
    }
    
    match (base_address, end_address) {
        (Some(base), Some(end)) => {
            Ok(ModuleInfo {
                base_address: base,
                size: end - base,
            })
        }
        _ => Err(ModuleError::NotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_get_current_executable() {
        // 尝试获取当前可执行文件的信息
        #[cfg(target_os = "windows")]
        let result = get_module_info("test.exe");
        
        #[cfg(target_os = "linux")]
        let result = get_module_info("test");
        
        match result {
            Ok(info) => {
                println!("Base Address: 0x{:X}", info.base_address);
                println!("Size: {} bytes", info.size);
                assert!(info.base_address > 0);
                assert!(info.size > 0);
            }
            Err(e) => println!("Error: {}", e),
        }
    }
}