use anyhow::Result;

#[cfg(target_os = "windows")]
mod win {
    use windows::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION};
    use core::ffi::c_void;
    use std::mem::MaybeUninit;

    pub unsafe fn module_base_from_ptr(ptr: *const u8) -> u64 {
        let mut mbi = MaybeUninit::<MEMORY_BASIC_INFORMATION>::uninit();
        let r = unsafe { VirtualQuery(
            Some(ptr as *const c_void),
            mbi.as_mut_ptr(),
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        ) };
        if r == 0 { return 0; }
        let mbi = unsafe { mbi.assume_init() };
        mbi.AllocationBase as u64
    }
}

#[cfg(target_os = "linux")]
mod lin {
    use libc::{c_void, Dl_info, dladdr};

    pub unsafe fn module_base_from_ptr(ptr: *const u8) -> u64 {
        let mut info: Dl_info = std::mem::zeroed();
        let ok = dladdr(ptr as *const c_void, &mut info as *mut Dl_info);
        if ok == 0 || info.dli_fbase.is_null() {
            0
        } else {
            info.dli_fbase as u64
        }
    }
}

pub fn get_module_base_from_pointer(ptr: u64) -> u64 {
  unsafe {

      #[cfg(target_os = "windows")]
      {
          win::module_base_from_ptr(ptr as *const u8)
      }

      #[cfg(target_os = "linux")]
      {
        use std::{mem::MaybeUninit};
          lin::module_base_from_ptr(ptr as *const u8)
      }

      #[cfg(not(any(target_os = "windows", target_os = "linux")))]
      {
          -1 // Unsupported platform
      }
  }
}
#[allow(dead_code)]
pub fn set_mem_access(ptr: u64, size: usize) -> Result<()> {
    unsafe {
        let addr = ptr as *const u8;
        region::protect(addr, size, region::Protection::READ_WRITE_EXECUTE).map_err(|e| anyhow::anyhow!("Failed to change memory protection: {}", e))
    }
}
