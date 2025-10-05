use std::os::raw::{c_void, c_char};

#[cfg(target_os = "windows")]
unsafe fn get_module_base_windows(ptr: usize) -> u64 {
    use std::{mem::MaybeUninit};

    #[repr(C)]
    struct MemoryBasicInformation {
        base_address: *mut c_void,
        allocation_base: *mut c_void,
        allocation_protect: u32,
        region_size: usize,
        state: u32,
        protect: u32,
        type_: u32,
    }

    unsafe extern "system" {
        fn VirtualQuery(
            address: *const c_void,
            buffer: *mut MemoryBasicInformation,
            length: usize,
        ) -> usize;
    }

    let mut mbi = MaybeUninit::<MemoryBasicInformation>::uninit();
    let ret = unsafe {

        VirtualQuery(
            ptr as *const c_void,
            mbi.as_mut_ptr(),
            std::mem::size_of::<MemoryBasicInformation>(),
        )
    };

    if ret == 0 {
        return 0;
    }

    let mbi = unsafe { mbi.assume_init() };
    unsafe { mbi.allocation_base as u64 }
}


#[cfg(target_os = "linux")]
unsafe fn get_module_base_linux(ptr: *const c_void) -> u64 {
    use std::{mem::MaybeUninit};
    #[repr(C)]
    struct link_map {
        l_addr: usize,
        l_name: *const c_char,
        l_ld: *const c_void,
        l_next: *const link_map,
        l_prev: *const link_map,
    }

    const RTLD_DI_LINKMAP: i32 = 2;

    unsafe extern "C" {
        fn dlinfo(handle: *mut c_void, request: i32, info: *mut c_void) -> i32;
        fn dlopen(filename: *const c_char, flag: i32) -> *mut c_void;
        fn dladdr(addr: *const c_void, info: *mut Dl_info) -> i32;
    }

    #[repr(C)]
    struct Dl_info {
        dli_fname: *const c_char,
        dli_fbase: *mut c_void,
        dli_sname: *const c_char,
        dli_saddr: *mut c_void,
    }

    let mut info = MaybeUninit::<Dl_info>::uninit();
    if dladdr(ptr, info.as_mut_ptr()) == 0 {
        return 0;
    }

    let info = info.assume_init();
    
    // Try to get more accurate base address using dlinfo
    const RTLD_LAZY: i32 = 0x00001;
    let handle = dlopen(info.dli_fname, RTLD_LAZY);
    
    if !handle.is_null() {
        let mut lm: *const link_map = std::ptr::null();
        if dlinfo(handle, RTLD_DI_LINKMAP, &mut lm as *mut _ as *mut c_void) == 0 && !lm.is_null() {
            return (*lm).l_addr.try_into().unwrap();
        }
    }

    // Fallback to dli_fbase
    info.dli_fbase as u64
}

pub fn get_module_base_from_pointer(ptr: u64) -> u64 {
  unsafe {

      #[cfg(target_os = "windows")]
      {
          get_module_base_windows(ptr as usize)
      }

      #[cfg(target_os = "linux")]
      {
        use std::{mem::MaybeUninit};
          get_module_base_linux(ptr as *const c_void)
      }

      #[cfg(not(any(target_os = "windows", target_os = "linux")))]
      {
          -1 // Unsupported platform
      }
  }
}