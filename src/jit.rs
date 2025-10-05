use anyhow::{Result, Context};
use iced_x86::{Instruction, Code, Register, Encoder};
use std::ptr;

/// Cross-platform executable memory allocator
pub struct ExecutableMemory {
    ptr: *mut u8,
    size: usize,
}

impl ExecutableMemory {
    /// Allocate executable memory with the specified size
    pub fn new(size: usize) -> Result<Self> {
        let ptr = unsafe { allocate_executable_memory(size)? };
        Ok(Self { ptr, size })
    }

    /// Get the address of the allocated memory
    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Get the address as u64
    pub fn address(&self) -> u64 {
        self.ptr as u64
    }

    /// Write bytes to the executable memory
    pub fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > self.size {
            anyhow::bail!("Buffer size {} exceeds allocated size {}", bytes.len(), self.size);
        }
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr, bytes.len());
        }
        Ok(())
    }

    /// Get size of allocated memory
    pub fn size(&self) -> usize {
        self.size
    }
}

impl Drop for ExecutableMemory {
    fn drop(&mut self) {
        unsafe {
            let _ = free_executable_memory(self.ptr, self.size);
        }
    }
}

unsafe impl Send for ExecutableMemory {}
unsafe impl Sync for ExecutableMemory {}

/// Platform-specific memory allocation
#[cfg(target_os = "windows")]
unsafe fn allocate_executable_memory(size: usize) -> Result<*mut u8> {
    use std::ptr::null_mut;
    
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualAlloc(
            lpaddress: *mut u8,
            dwsize: usize,
            flallocationtype: u32,
            flprotect: u32,
        ) -> *mut u8;
    }
    
    let ptr = unsafe {
        VirtualAlloc(
            null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    
    if ptr.is_null() {
        anyhow::bail!("Failed to allocate executable memory");
    }
    
    Ok(ptr)
}

#[cfg(target_os = "linux")]
unsafe fn allocate_executable_memory(size: usize) -> Result<*mut u8> {
    const PROT_READ: i32 = 1;
    const PROT_WRITE: i32 = 2;
    const PROT_EXEC: i32 = 4;
    const MAP_PRIVATE: i32 = 0x02;
    const MAP_ANONYMOUS: i32 = 0x20;
    
    unsafe extern "C" {
        fn mmap(
            addr: *mut u8,
            len: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: i64,
        ) -> *mut u8;
    }
    
    let ptr = mmap(
        ptr::null_mut(),
        size,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0,
    );
    
    if ptr as isize == -1 {
        anyhow::bail!("Failed to allocate executable memory");
    }
    
    Ok(ptr)
}

#[cfg(target_os = "windows")]
unsafe fn free_executable_memory(ptr: *mut u8, _size: usize) -> Result<()> {
    const MEM_RELEASE: u32 = 0x8000;
    
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn VirtualFree(lpaddress: *mut u8, dwsize: usize, dwfreetype: u32) -> i32;
    }
    
    if unsafe { VirtualFree(ptr, 0, MEM_RELEASE) } == 0 {
        anyhow::bail!("Failed to free executable memory");
    }
    
    Ok(())
}

#[cfg(target_os = "linux")]
unsafe fn free_executable_memory(ptr: *mut u8, size: usize) -> Result<()> {
    unsafe extern "C" {
        fn munmap(addr: *mut u8, len: usize) -> i32;
    }
    
    if munmap(ptr, size) != 0 {
        anyhow::bail!("Failed to free executable memory");
    }
    
    Ok(())
}

/// JIT Trampoline Generator
pub struct JitTrampoline {
    memory: ExecutableMemory,
}

impl JitTrampoline {
    pub fn new(target_address: u64) -> Result<Self> {
        let code = Self::generate_jump(target_address)?;
        let mut memory = ExecutableMemory::new(code.len())
            .context("Failed to allocate executable memory for trampoline")?;
        memory.write(&code)?;
        
        Ok(Self { memory })
    }

    fn generate_jump(target_address: u64) -> Result<Vec<u8>> {
        Self::generate_jump_x64(target_address)
    }

    fn generate_jump_x64(target_address: u64) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new(64);

        // preserve space for safetyhook trampoline
        for i in 0..20 {
            let nop_instr = Instruction::with(Code::Nopw);
            encoder.encode(&nop_instr, 0)?;
        }
        
        // mov rax, imm64
        let mov_instr = Instruction::with2(
            Code::Mov_r64_imm64,
            Register::RAX,
            target_address,
        )?;
        encoder.encode(&mov_instr, 0)?;
        
        // jmp rax
        let jmp_instr = Instruction::with1(Code::Jmp_rm64, Register::RAX)?;
        encoder.encode(&jmp_instr, 0)?;
        
        let bytes = encoder.take_buffer().to_vec();
        Ok(bytes)
    }

    /// Get the address of the trampoline
    pub fn address(&self) -> u64 {
        self.memory.address()
    }

    pub unsafe fn as_fn_ptr<F>(&self) -> F {
        unsafe { std::mem::transmute_copy(&self.memory.as_ptr()) }
    }

    pub fn size(&self) -> usize {
        self.memory.size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test function that returns a specific value
    extern "C" fn test_function_returns_42() -> i32 {
        42
    }

    extern "C" fn test_function_add(a: i32, b: i32) -> i32 {
        a + b
    }

    extern "C" fn test_function_no_args() -> i32 {
        12345
    }

    #[test]
    fn test_trampoline_basic_64bit() -> Result<()> {
        let target_addr = test_function_returns_42 as u64;
        let trampoline = JitTrampoline::new(target_addr)?;
        
        // Cast the trampoline to a function pointer and call it
        let trampoline_fn: extern "C" fn() -> i32 = unsafe { trampoline.as_fn_ptr() };
        let result = trampoline_fn();
        
        assert_eq!(result, 42, "Trampoline should call the target function correctly");
        Ok(())
    }

    #[test]
    fn test_trampoline_with_args_64bit() -> Result<()> {
        let target_addr = test_function_add as u64;
        let trampoline = JitTrampoline::new(target_addr)?;
        
        let trampoline_fn: extern "C" fn(i32, i32) -> i32 = unsafe { trampoline.as_fn_ptr() };
        let result = trampoline_fn(10, 32);
        
        assert_eq!(result, 42, "Trampoline should correctly pass arguments");
        Ok(())
    }

    #[test]
    fn test_trampoline_no_args_64bit() -> Result<()> {
        let target_addr = test_function_no_args as u64;
        let trampoline = JitTrampoline::new(target_addr)?;
        
        let trampoline_fn: extern "C" fn() -> i32 = unsafe { trampoline.as_fn_ptr() };
        let result = trampoline_fn();
        
        assert_eq!(result, 12345, "Trampoline should work with no-arg functions");
        Ok(())
    }

    #[test]
    fn test_multiple_trampolines() -> Result<()> {
        // Create multiple trampolines to ensure memory management works
        let trampoline1 = JitTrampoline::new(test_function_returns_42 as u64)?;
        let trampoline2 = JitTrampoline::new(test_function_no_args as u64)?;
        
        let fn1: extern "C" fn() -> i32 = unsafe { trampoline1.as_fn_ptr() };
        let fn2: extern "C" fn() -> i32 = unsafe { trampoline2.as_fn_ptr() };
        
        assert_eq!(fn1(), 42);
        assert_eq!(fn2(), 12345);
        
        Ok(())
    }

    #[test]
    fn test_executable_memory_allocation() -> Result<()> {
        let mem = ExecutableMemory::new(64)?;
        assert!(!mem.as_ptr().is_null(), "Memory allocation should succeed");
        assert_eq!(mem.size(), 64, "Memory size should match requested size");
        Ok(())
    }

    #[test]
    fn test_executable_memory_write() -> Result<()> {
        let mut mem = ExecutableMemory::new(16)?;
        let data = vec![0x90, 0x90, 0x90, 0x90]; // NOP instructions
        mem.write(&data)?;
        
        // Verify the data was written
        unsafe {
            let slice = std::slice::from_raw_parts(mem.as_ptr(), data.len());
            assert_eq!(slice, &data[..], "Written data should match");
        }
        
        Ok(())
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn test_trampoline_32bit() -> Result<()> {
        let target_addr = test_function_returns_42 as u64;
        let trampoline = JitTrampoline::new(target_addr, 32)?;
        
        let trampoline_fn: extern "C" fn() -> i32 = unsafe { trampoline.as_fn_ptr() };
        let result = trampoline_fn();
        
        assert_eq!(result, 42, "32-bit trampoline should work");
        Ok(())
    }

    #[test]
    fn test_trampoline_address_validity() -> Result<()> {
        let target_addr = test_function_returns_42 as u64;
        let trampoline = JitTrampoline::new(target_addr)?;
        
        let addr = trampoline.address();
        assert_ne!(addr, 0, "Trampoline address should be non-zero");
        assert_ne!(addr, target_addr, "Trampoline address should differ from target");
        
        Ok(())
    }
}
