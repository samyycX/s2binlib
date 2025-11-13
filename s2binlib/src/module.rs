#[derive(Debug)]
pub struct ModuleInfo {
    pub base_address: usize,
    pub size: usize,
}

#[derive(Debug)]
pub enum ModuleError {
    NotFound,
    InvalidBase,
    SystemError(String),
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ModuleError::NotFound => write!(f, "Module not found"),
            ModuleError::InvalidBase => write!(f, "Invalid module base address"),
            ModuleError::SystemError(msg) => write!(f, "System error: {}", msg),
        }
    }
}

impl std::error::Error for ModuleError {}

pub fn get_module_info(module_base: u64) -> Result<ModuleInfo, ModuleError> {
    if module_base == 0 || module_base > usize::MAX as u64 {
        return Err(ModuleError::InvalidBase);
    }

    #[cfg(target_os = "windows")]
    {
        get_module_info_windows(module_base as usize)
    }

    #[cfg(target_os = "linux")]
    {
        get_module_info_linux(module_base as usize)
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        Err(ModuleError::SystemError("Unsupported platform".to_string()))
    }
}

#[cfg(target_os = "windows")]
fn get_module_info_windows(module_base: usize) -> Result<ModuleInfo, ModuleError> {
    use std::mem;
    use winapi::shared::minwindef::{FALSE, HMODULE};
    use winapi::um::processthreadsapi::GetCurrentProcess;
    use winapi::um::psapi::{GetModuleInformation, MODULEINFO};

    if module_base == 0 {
        return Err(ModuleError::InvalidBase);
    }

    unsafe {
        let h_module: HMODULE = module_base as HMODULE;

        let mut mod_info: MODULEINFO = mem::zeroed();
        let result = GetModuleInformation(
            GetCurrentProcess(),
            h_module,
            &mut mod_info,
            mem::size_of::<MODULEINFO>() as u32,
        );

        if result == FALSE {
            const ERROR_INVALID_HANDLE: i32 = 6;
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_INVALID_HANDLE) {
                return Err(ModuleError::NotFound);
            }
            return Err(ModuleError::SystemError(format!(
                "GetModuleInformation failed with error: {error}"
            )));
        }

        Ok(ModuleInfo {
            base_address: mod_info.lpBaseOfDll as usize,
            size: mod_info.SizeOfImage as usize,
        })
    }
}

#[cfg(target_os = "linux")]
fn get_module_info_linux(module_base: usize) -> Result<ModuleInfo, ModuleError> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    if module_base == 0 {
        return Err(ModuleError::InvalidBase);
    }

    let maps_file = File::open("/proc/self/maps")
        .map_err(|e| ModuleError::SystemError(format!("Cannot open /proc/self/maps: {}", e)))?;

    let reader = BufReader::new(maps_file);
    let mut base_address: Option<usize> = None;
    let mut end_address: Option<usize> = None;
    let mut module_path: Option<String> = None;
    let mut module_dev: Option<String> = None;
    let mut module_inode: Option<String> = None;

    for line in reader.lines() {
        let line = line.map_err(|e| ModuleError::SystemError(format!("Read error: {}", e)))?;

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
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

        let current_dev = parts.get(3).map(|s| s.to_string());
        let current_inode = parts.get(4).map(|s| s.to_string());
        let current_path = if parts.len() > 5 {
            Some(parts[5..].join(" "))
        } else {
            None
        };

        if base_address.is_none() {
            if start == module_base {
                base_address = Some(start);
                end_address = Some(end);
                module_path = current_path;
                module_dev = current_dev;
                module_inode = current_inode;
            }
            continue;
        }

        let matches_path = match (&module_path, &current_path) {
            (Some(expected), Some(actual)) => expected == actual,
            (None, None) => true,
            _ => false,
        };

        let matches_identity = match (&module_dev, &module_inode, &current_dev, &current_inode) {
            (Some(expected_dev), Some(expected_inode), Some(dev), Some(inode)) => {
                expected_dev == dev && expected_inode == inode
            }
            _ => false,
        };

        let contiguous = end_address.map_or(false, |current_end| start == current_end);

        if matches_path || matches_identity || contiguous {
            match end_address {
                Some(ref mut stored_end) if end > *stored_end => *stored_end = end,
                None => end_address = Some(end),
                _ => {}
            }
            continue;
        }

        if start > module_base {
            break;
        }
    }

    match (base_address, end_address) {
        (Some(base), Some(end)) if end > base => Ok(ModuleInfo {
            base_address: base,
            size: end - base,
        }),
        _ => Err(ModuleError::NotFound),
    }
}
