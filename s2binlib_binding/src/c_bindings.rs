/************************************************************************************
 *  S2BinLib - A static library that helps resolving memory from binary file
 *  and map to absolute memory address, targeting source 2 game engine.
 *  Copyright (C) 2025  samyyc
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 ***********************************************************************************/

use once_cell::sync::Lazy;
use std::ffi::{CStr, c_char, c_void};
use std::sync::Mutex;

use s2binlib::S2BinLib;

/// Macro for debug logging in C bindings when the debug_c_bindings feature is enabled
#[cfg(feature = "debug_c_bindings")]
macro_rules! c_debug {
    ($($arg:tt)*) => {
        println!("[S2BinLib C Binding Debug] {}", format!($($arg)*));
    };
}

#[cfg(not(feature = "debug_c_bindings"))]
macro_rules! c_debug {
    ($($arg:tt)*) => {};
}

/// Macro to return an error code with optional debug message
macro_rules! return_error {
    ($code:expr, $msg:expr) => {{
        c_debug!("Error {}: {} (at {}:{})", $code, $msg, file!(), line!());
        return $code;
    }};
    ($code:expr) => {{
        c_debug!("Error {} (at {}:{})", $code, file!(), line!());
        return $code;
    }};
}

/// Global S2BinLib instance
static S2BINLIB: Lazy<Mutex<Option<S2BinLib<'static>>>> = Lazy::new(|| Mutex::new(None));

/// Initialize the global S2BinLib instance
///
/// The operating system is automatically detected at runtime.
/// Can be called multiple times to reinitialize with different parameters.
///
/// # Parameters
/// * `game_path` - Path to the game directory (null-terminated C string)
/// * `game_type` - Game type identifier (null-terminated C string)
///
/// # Returns
/// * 0 on success
/// * -2 if invalid parameters
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
/// The caller must ensure that the pointers are valid and point to null-terminated C strings.
///
/// # Example
/// ```c
/// int result = s2binlib_initialize("C:/Games/MyGame", "dota2");
/// if (result != 0) {
///     // Handle error
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_initialize(game_path: *const c_char, game_type: *const c_char) -> i32 {
    unsafe {
        // validate input pointers
        if game_path.is_null() || game_type.is_null() {
            return_error!(-2, "invalid parameters: game_path or game_type is null");
        }

        // Convert C strings to Rust strings
        let game_path_str = match CStr::from_ptr(game_path).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert game_path to UTF-8 string"),
        };

        let game_type_str = match CStr::from_ptr(game_type).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert game_type to UTF-8 string"),
        };

        // Automatically detect the operating system
        let os_str = if cfg!(target_os = "windows") {
            "windows"
        } else if cfg!(target_os = "linux") {
            "linux"
        } else {
            return_error!(-2, "Unsupported operating system");
        };

        // Initialize the global instance
        let mut s2binlib = match S2BINLIB.lock() {
            Ok(lib) => lib,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        *s2binlib = Some(S2BinLib::new(game_path_str, game_type_str, os_str));
        0
    }
}

/// Initialize the global S2BinLib instance with explicit OS parameter
///
/// Can be called multiple times to reinitialize with different parameters.
///
/// # Parameters
/// * `game_path` - Path to the game directory (null-terminated C string)
/// * `game_type` - Game type identifier (null-terminated C string)
/// * `os` - Operating system ("windows" or "linux") (null-terminated C string)
///
/// # Returns
/// * 0 on success
/// * -2 if invalid parameters
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
/// The caller must ensure that the pointers are valid and point to null-terminated C strings.
///
/// # Example
/// ```c
/// int result = s2binlib_initialize_with_os("C:/Games/MyGame", "dota2", "windows");
/// if (result != 0) {
///     // Handle error
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_initialize_with_os(
    game_path: *const c_char,
    game_type: *const c_char,
    os: *const c_char,
) -> i32 {
    unsafe {
        // validate input pointers
        if game_path.is_null() || game_type.is_null() || os.is_null() {
            return_error!(-2, "invalid parameters: game_path, game_type or os is null");
        }

        // Convert C strings to Rust strings
        let game_path_str = match CStr::from_ptr(game_path).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert game_path to UTF-8 string"),
        };

        let game_type_str = match CStr::from_ptr(game_type).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert game_type to UTF-8 string"),
        };

        let os_str = match CStr::from_ptr(os).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert os to UTF-8 string"),
        };

        // Initialize the global instance
        let mut s2binlib = match S2BINLIB.lock() {
            Ok(lib) => lib,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        *s2binlib = Some(S2BinLib::new(game_path_str, game_type_str, os_str));
        0
    }
}

/// Scan for a pattern in the specified binary
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to scan (e.g., "server", "client") (null-terminated C string)
/// * `pattern` - Pattern string with wildcards (e.g., "48 89 5C 24 ? 48 89 74 24 ?") (null-terminated C string)
/// * `result` - Pointer to store the resulting address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary
/// * -4 if pattern not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
/// The caller must ensure that the pointers are valid.
///
/// # Example
/// ```c
/// void* address;
/// int result = s2binlib_pattern_scan("server", "48 89 5C 24 ? 48 89 74", &address);
/// if (result == 0) {
///     printf("Found at: %p\n", address);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_pattern_scan(
    binary_name: *const c_char,
    pattern: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        // validate input pointers
        if binary_name.is_null() || pattern.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, pattern or result is null"
            );
        }

        // Convert C strings to Rust strings
        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let pattern_str = match CStr::from_ptr(pattern).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        // Get the global instance
        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        // Load binary if not already loaded
        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        // Perform pattern scan
        match s2binlib.pattern_scan(binary_name_str, pattern_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find a vtable by class name in the specified binary
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (e.g., "server", "client") (null-terminated C string)
/// * `vtable_name` - Class name to search for (null-terminated C string)
/// * `result` - Pointer to store the resulting vtable address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary
/// * -4 if vtable not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
/// The caller must ensure that the pointers are valid.
///
/// # Example
/// ```c
/// void* vtable_addr;
/// int result = s2binlib_find_vtable("server", "CBaseEntity", &vtable_addr);
/// if (result == 0) {
///     printf("VTable at: %p\n", vtable_addr);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_vtable(
    binary_name: *const c_char,
    vtable_name: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        // validate input pointers
        if binary_name.is_null() || vtable_name.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, vtable_name or result is null"
            );
        }

        // Convert C strings to Rust strings
        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let vtable_name_str = match CStr::from_ptr(vtable_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        // Get the global instance
        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        // Load binary if not already loaded
        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        // Find vtable
        match s2binlib.find_vtable(binary_name_str, vtable_name_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find a symbol by name in the specified binary
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (e.g., "server", "client") (null-terminated C string)
/// * `symbol_name` - Symbol name to search for (null-terminated C string)
/// * `result` - Pointer to store the resulting symbol address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if symbol not found
/// * -4 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
/// The caller must ensure that the pointers are valid.
///
/// # Example
/// ```c
/// void* symbol_addr;
/// int result = s2binlib_find_symbol("server", "CreateInterface", &symbol_addr);
/// if (result == 0) {
///     printf("Symbol at: %p\n", symbol_addr);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_symbol(
    binary_name: *const c_char,
    symbol_name: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        // validate input pointers
        if binary_name.is_null() || symbol_name.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, symbol_name or result is null"
            );
        }

        // Convert C strings to Rust strings
        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let symbol_name_str = match CStr::from_ptr(symbol_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        // Get the global instance
        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        // Load binary if not already loaded
        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        // Find symbol
        match s2binlib.find_symbol(binary_name_str, symbol_name_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-3, "Failed to load binary or operation failed"),
        }
    }
}

/// Manually set the base address for a module from a pointer
///
/// This allows overriding the automatic base address detection for a module.
/// Useful when you need to force a specific base address or when the module is loaded
/// in a non-standard way. The function will automatically detect the module base from
/// the provided pointer.
///
/// # Parameters
/// * `binary_name` - Name of the binary (e.g., "server", "client") (null-terminated C string)
/// * `pointer` - The pointer inside the specified module
///
/// # Returns
/// * 0 on success
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// int result = s2binlib_set_module_base_from_pointer("server", 0x140001000);
/// if (result == 0) {
///     printf("Server base address set successfully\n");
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_set_module_base_from_pointer(
    binary_name: *const c_char,
    pointer: *mut c_void,
) -> i32 {
    unsafe {
        // validate input pointers
        if binary_name.is_null() {
            return_error!(-2, "invalid parameter: binary_name is null");
        }

        // Convert C strings to Rust strings
        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        // Get the global instance
        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        // Set the base address for the module
        s2binlib.set_module_base_from_pointer(binary_name_str, pointer as u64);
        0
    }
}

/// Clear manually set base address for a module
///
/// After calling this, the module will use automatic base address detection again.
///
/// # Parameters
/// * `binary_name` - Name of the binary (e.g., "server", "client") (null-terminated C string)
///
/// # Returns
/// * 0 on success
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// int result = s2binlib_clear_module_base_address("server");
/// if (result == 0) {
///     printf("Server base address cleared\n");
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_clear_module_base_address(binary_name: *const c_char) -> i32 {
    unsafe {
        if binary_name.is_null() {
            return_error!(-2, "invalid parameter: binary_name is null");
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        s2binlib.clear_module_base_address(binary_name_str);
        0
    }
}

/// Set a custom binary path for a specific binary and operating system
///
/// This allows overriding the default binary path resolution for a specific binary.
/// You can specify different paths for Windows and Linux builds.
///
/// # Parameters
/// * `binary_name` - Name of the binary (e.g., "server", "client") (null-terminated C string)
/// * `path` - The custom file path to the binary (null-terminated C string)
/// * `os` - Operating system identifier ("windows" or "linux") (null-terminated C string)
///
/// # Returns
/// * 0 on success
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -4 if unsupported OS specified
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// int result = s2binlib_set_custom_binary_path("server", "/custom/path/server.dll", "windows");
/// if (result == 0) {
///     printf("Custom binary path set successfully\n");
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_set_custom_binary_path(
    binary_name: *const c_char,
    path: *const c_char,
    os: *const c_char,
) -> i32 {
    unsafe {
        // validate input pointers
        if binary_name.is_null() || path.is_null() || os.is_null() {
            return_error!(-2, "invalid parameters: binary_name, path or os is null");
        }

        // Convert C strings to Rust strings
        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let path_str = match CStr::from_ptr(path).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let os_str = match CStr::from_ptr(os).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        // Get the global instance
        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        // Set the custom binary path
        match s2binlib.set_custom_binary_path(binary_name_str, path_str, os_str) {
            Ok(_) => 0,
            Err(_) => return_error!(-4, "Pattern not found or operation failed"), // Unsupported OS
        }
    }
}

/// Get the module base address
///
/// Returns the base address of a loaded module. If a manual base address was set
/// using set_module_base_from_pointer, that value will be returned. Otherwise,
/// the function attempts to find the base address from the running process.
///
/// # Parameters
/// * `binary_name` - Name of the binary (e.g., "server", "client") (null-terminated C string)
/// * `result` - Pointer to store the resulting base address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if module not found or not loaded
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* base_addr;
/// int result = s2binlib_get_module_base_address("server", &base_addr);
/// if (result == 0) {
///     printf("Module base: %p\n", base_addr);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_get_module_base_address(
    binary_name: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || result.is_null() {
            return_error!(-2, "invalid parameters: binary_name or result is null");
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_ref() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        match s2binlib.get_module_base_address(binary_name_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-3, "Failed to load binary or operation failed"),
        }
    }
}

/// Check if a binary is already loaded
///
/// # Parameters
/// * `binary_name` - Name of the binary to check (null-terminated C string)
///
/// # Returns
/// * 1 if loaded
/// * 0 if not loaded
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// int loaded = s2binlib_is_binary_loaded("server");
/// if (loaded == 1) {
///     printf("Server is loaded\n");
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_is_binary_loaded(binary_name: *const c_char) -> i32 {
    unsafe {
        if binary_name.is_null() {
            return_error!(-2, "invalid parameter: binary_name is null");
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_ref() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if s2binlib.is_binary_loaded(binary_name_str) {
            1
        } else {
            0
        }
    }
}

/// Load a binary into memory
///
/// Loads the specified binary file into memory for analysis. The binary path
/// is automatically determined based on the game path and type set during initialization.
/// If the binary is already loaded, this function does nothing.
///
/// # Parameters
/// * `binary_name` - Name of the binary to load (null-terminated C string)
///
/// # Returns
/// * 0 on success
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// int result = s2binlib_load_binary("server");
/// if (result == 0) {
///     printf("Server loaded successfully\n");
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_load_binary(binary_name: *const c_char) -> i32 {
    unsafe {
        if binary_name.is_null() {
            return_error!(-2, "invalid parameter: binary_name is null");
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        s2binlib.load_binary(binary_name_str);
        0
    }
}

/// Get the full path to a binary file
///
/// Returns the full filesystem path where the binary file is expected to be located,
/// based on the game path, game type, and operating system.
///
/// # Parameters
/// * `binary_name` - Name of the binary (null-terminated C string)
/// * `buffer` - Buffer to store the path string
/// * `buffer_size` - Size of the buffer
///
/// # Returns
/// * 0 on success (path written to buffer)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if buffer too small
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// char path[512];
/// int result = s2binlib_get_binary_path("server", path, sizeof(path));
/// if (result == 0) {
///     printf("Binary path: %s\n", path);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_get_binary_path(
    binary_name: *const c_char,
    buffer: *mut c_char,
    buffer_size: usize,
) -> i32 {
    unsafe {
        if binary_name.is_null() || buffer.is_null() || buffer_size == 0 {
            return -2;
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_ref() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        let path = s2binlib.get_binary_path(binary_name_str);
        let path_bytes = path.as_bytes();

        if path_bytes.len() + 1 > buffer_size {
            return -3; // Buffer too small
        }

        std::ptr::copy_nonoverlapping(path_bytes.as_ptr(), buffer as *mut u8, path_bytes.len());
        *(buffer.add(path_bytes.len())) = 0; // Null terminator

        0
    }
}

/// Find a vtable by class name and return its relative virtual address
///
/// Searches for a vtable (virtual function table) by the class name and returns
/// its relative virtual address (RVA) in the binary. This is the address as it appears in
/// the binary file, not the runtime memory address.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (null-terminated C string)
/// * `vtable_name` - Class name to search for (null-terminated C string)
/// * `result` - Pointer to store the resulting vtable relative virtual address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary
/// * -4 if vtable not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* vtable_rva;
/// int result = s2binlib_find_vtable_rva("server", "CBaseEntity", &vtable_rva);
/// if (result == 0) {
///     printf("VTable RVA: %p\n", vtable_rva);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_vtable_rva(
    binary_name: *const c_char,
    vtable_name: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || vtable_name.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, vtable_name or result is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let vtable_name_str = match CStr::from_ptr(vtable_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.find_vtable_rva(binary_name_str, vtable_name_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find a vtable by mangled name and return its relative virtual address
///
/// Searches for a vtable using the mangled/decorated RTTI name directly.
/// Unlike find_vtable_rva which auto-decorates the name, this function uses
/// the provided name as-is.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (null-terminated C string)
/// * `vtable_name` - Mangled RTTI name to search for (null-terminated C string)
/// * `result` - Pointer to store the resulting vtable relative virtual address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary
/// * -4 if vtable not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* vtable_rva;
/// int result = s2binlib_find_vtable_mangled_rva("server", ".?AVCBaseEntity@@", &vtable_rva);
/// if (result == 0) {
///     printf("VTable RVA: %p\n", vtable_rva);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_vtable_mangled_rva(
    binary_name: *const c_char,
    vtable_name: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || vtable_name.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, vtable_name or result is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let vtable_name_str = match CStr::from_ptr(vtable_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.find_vtable_mangled_rva(binary_name_str, vtable_name_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find a vtable by mangled name and return its runtime memory address
///
/// Searches for a vtable using the mangled/decorated RTTI name directly and
/// returns its runtime memory address.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (null-terminated C string)
/// * `vtable_name` - Mangled RTTI name to search for (null-terminated C string)
/// * `result` - Pointer to store the resulting vtable memory address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary
/// * -4 if vtable not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* vtable_addr;
/// int result = s2binlib_find_vtable_mangled("server", ".?AVCBaseEntity@@", &vtable_addr);
/// if (result == 0) {
///     printf("VTable at: %p\n", vtable_addr);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_vtable_mangled(
    binary_name: *const c_char,
    vtable_name: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || vtable_name.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, vtable_name or result is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let vtable_name_str = match CStr::from_ptr(vtable_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.find_vtable_mangled(binary_name_str, vtable_name_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find a nested vtable (2 levels) by class names and return its relative virtual address
///
/// Searches for a vtable of a nested class (e.g., Class1::Class2).
/// The function automatically decorates the names according to the platform's
/// RTTI name mangling scheme.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (null-terminated C string)
/// * `class1_name` - Outer class name (null-terminated C string)
/// * `class2_name` - Inner/nested class name (null-terminated C string)
/// * `result` - Pointer to store the resulting vtable relative virtual address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary
/// * -4 if vtable not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* vtable_rva;
/// int result = s2binlib_find_vtable_nested_2_rva("server", "CEntitySystem", "CEntitySubsystem", &vtable_rva);
/// if (result == 0) {
///     printf("Nested VTable RVA: %p\n", vtable_rva);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_vtable_nested_2_rva(
    binary_name: *const c_char,
    class1_name: *const c_char,
    class2_name: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null()
            || class1_name.is_null()
            || class2_name.is_null()
            || result.is_null()
        {
            return_error!(
                -2,
                "invalid parameters: binary_name, class names or result is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let class1_name_str = match CStr::from_ptr(class1_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let class2_name_str = match CStr::from_ptr(class2_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.find_vtable_nested_2_rva(binary_name_str, class1_name_str, class2_name_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find a nested vtable (2 levels) by class names and return its runtime memory address
///
/// Searches for a vtable of a nested class (e.g., Class1::Class2) and returns
/// its runtime memory address.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (null-terminated C string)
/// * `class1_name` - Outer class name (null-terminated C string)
/// * `class2_name` - Inner/nested class name (null-terminated C string)
/// * `result` - Pointer to store the resulting vtable memory address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary
/// * -4 if vtable not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* vtable_addr;
/// int result = s2binlib_find_vtable_nested_2("server", "CEntitySystem", "CEntitySubsystem", &vtable_addr);
/// if (result == 0) {
///     printf("Nested VTable at: %p\n", vtable_addr);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_vtable_nested_2(
    binary_name: *const c_char,
    class1_name: *const c_char,
    class2_name: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null()
            || class1_name.is_null()
            || class2_name.is_null()
            || result.is_null()
        {
            return_error!(
                -2,
                "invalid parameters: binary_name, class names or result is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let class1_name_str = match CStr::from_ptr(class1_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let class2_name_str = match CStr::from_ptr(class2_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.find_vtable_nested_2(binary_name_str, class1_name_str, class2_name_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Get the number of virtual functions in a vtable
///
/// Returns the count of virtual functions (vfuncs) in the specified vtable.
/// This counts valid function pointers in the vtable until it encounters a null
/// or invalid pointer.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (e.g., "server", "client") (null-terminated C string)
/// * `vtable_name` - Name of the vtable/class to search for (null-terminated C string)
/// * `result` - Pointer to store the resulting count of virtual functions
///
/// # Returns
/// * `0` - Success, result contains the vfunc count
/// * `-1` - S2BinLib not initialized
/// * `-2` - invalid input (null pointer or invalid UTF-8)
/// * `-4` - Operation failed (vtable not found or other error)
/// * `-5` - Failed to acquire lock
///
/// # Example
/// ```c
/// size_t vfunc_count;
/// int result = s2binlib_get_vtable_vfunc_count("server", "CBaseEntity", &vfunc_count);
/// if (result == 0) {
///     printf("VTable has %zu virtual functions\n", vfunc_count);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_get_vtable_vfunc_count(
    binary_name: *const c_char,
    vtable_name: *const c_char,
    result: *mut usize,
) -> i32 {
    unsafe {
        if binary_name.is_null() || vtable_name.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, vtable_name or result is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let vtable_name_str = match CStr::from_ptr(vtable_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.get_vtable_vfunc_count(binary_name_str, vtable_name_str) {
            Ok(count) => {
                *result = count;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Get the number of virtual functions in a vtable by relative virtual address
///
/// Returns the count of virtual functions (vfuncs) in a vtable at the specified
/// relative virtual address. This counts valid function pointers in the vtable until it
/// encounters a null or invalid pointer.
///
/// Unlike get_vtable_vfunc_count, this function takes a relative virtual address directly
/// instead of looking up the vtable by name.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary (e.g., "server", "client") (null-terminated C string)
/// * `vtable_rva` - Virtual address of the vtable
/// * `result` - Pointer to store the resulting count of virtual functions
///
/// # Returns
/// * `0` - Success, result contains the vfunc count
/// * `-1` - S2BinLib not initialized
/// * `-2` - invalid input (null pointer or invalid UTF-8)
/// * `-4` - Operation failed (invalid address or other error)
/// * `-5` - Failed to acquire lock
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
/// The caller must ensure that the pointers are valid.
///
/// # Example
/// ```c
/// void* vtable_rva;
/// // First get the vtable relative virtual address
/// s2binlib_find_vtable_rva("server", "CBaseEntity", &vtable_rva);
///
/// // Then count its virtual functions
/// size_t vfunc_count;
/// int result = s2binlib_get_vtable_vfunc_count_by_rva("server", (uint64_t)vtable_rva, &vfunc_count);
/// if (result == 0) {
///     printf("VTable has %zu virtual functions\n", vfunc_count);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_get_vtable_vfunc_count_by_rva(
    binary_name: *const c_char,
    vtable_rva: u64,
    result: *mut usize,
) -> i32 {
    unsafe {
        if binary_name.is_null() || result.is_null() {
            return_error!(-2, "invalid parameters: binary_name or result is null");
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.get_vtable_vfunc_count_by_rva(binary_name_str, vtable_rva) {
            Ok(count) => {
                *result = count;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Pattern scan and return the relative virtual address
///
/// Scans for a byte pattern in the specified binary and returns the relative virtual address (RVA)
/// where the pattern was found. The RVA is the address as it appears in the binary file,
/// not the runtime memory address.
///
/// Pattern format: hex bytes separated by spaces, use '?' for wildcards
/// Example: "48 89 5C 24 ? 48 89 74 24 ?"
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to scan (null-terminated C string)
/// * `pattern` - Pattern string with wildcards (null-terminated C string)
/// * `result` - Pointer to store the resulting relative virtual address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary
/// * -4 if pattern not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* rva;
/// int result = s2binlib_pattern_scan_rva("server", "48 89 5C 24 ?", &rva);
/// if (result == 0) {
///     printf("Pattern found at RVA: %p\n", rva);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_pattern_scan_rva(
    binary_name: *const c_char,
    pattern: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || pattern.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, pattern or result is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let pattern_str = match CStr::from_ptr(pattern).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.pattern_scan_rva(binary_name_str, pattern_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Callback function type for pattern_scan_all functions
///
/// # Parameters
/// * `index` - The index of the current match (0-based)
/// * `address` - The found address (RVA or memory address depending on the function)
/// * `user_data` - User-provided data pointer
///
/// # Returns
/// * `true` to stop searching (found what you need)
/// * `false` to continue searching for more matches
pub type PatternScanCallback =
    extern "C" fn(index: usize, address: *mut c_void, user_data: *mut c_void) -> bool;

/// Find all occurrences of a pattern in a binary and return their relative virtual addresses
///
/// Scans the binary for all occurrences of the specified byte pattern and calls
/// the callback function for each match found. The callback receives the match index
/// and relative virtual addresses (RVA).
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to scan (null-terminated C string)
/// * `pattern` - Byte pattern to search for, with wildcards (e.g., "48 89 5C 24 ? 48 89 74")
/// * `callback` - Function pointer that will be called for each match
/// * `user_data` - User-provided pointer that will be passed to each callback invocation
///
/// # Returns
/// * 0 on success (at least one match found)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary
/// * -4 if pattern not found
/// * -5 if internal error
///
/// # Callback Return value
/// The callback should return:
/// * `true` to stop searching (if you found what you need)
/// * `false` to continue searching for more matches
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers and calls the callback function.
///
/// # Example
/// ```c
/// bool my_callback(size_t index, void* address, void* user_data) {
///     printf("Match #%zu found at RVA: %p\n", index, address);
///     int* count = (int*)user_data;
///     (*count)++;
///     return false; // Continue searching
/// }
///
/// int count = 0;
/// int result = s2binlib_pattern_scan_all_rva("server", "48 89 5C 24 ?", my_callback, &count);
/// if (result == 0) {
///     printf("Found %d matches\n", count);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_pattern_scan_all_rva(
    binary_name: *const c_char,
    pattern: *const c_char,
    callback: PatternScanCallback,
    user_data: *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || pattern.is_null() {
            return_error!(-2, "invalid parameters: binary_name or pattern is null");
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let pattern_str = match CStr::from_ptr(pattern).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.pattern_scan_all_rva(binary_name_str, pattern_str, |index, addr| {
            // Call the C callback function
            callback(index, addr as *mut c_void, user_data)
        }) {
            Ok(_) => 0,
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find all occurrences of a pattern in a binary and return their memory addresses
///
/// Scans the binary for all occurrences of the specified byte pattern and calls
/// the callback function for each match found. The callback receives the match index
/// and memory addresses (adjusted with module base address).
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to scan (null-terminated C string)
/// * `pattern` - Byte pattern to search for, with wildcards (e.g., "48 89 5C 24 ? 48 89 74")
/// * `callback` - Function pointer that will be called for each match
/// * `user_data` - User-provided pointer that will be passed to each callback invocation
///
/// # Returns
/// * 0 on success (at least one match found)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary
/// * -4 if pattern not found
/// * -5 if internal error
///
/// # Callback Return value
/// The callback should return:
/// * `true` to stop searching (if you found what you need)
/// * `false` to continue searching for more matches
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers and calls the callback function.
///
/// # Example
/// ```c
/// bool my_callback(size_t index, void* address, void* user_data) {
///     printf("Match #%zu found at memory address: %p\n", index, address);
///     int* count = (int*)user_data;
///     (*count)++;
///     return false; // Continue searching
/// }
///
/// int count = 0;
/// int result = s2binlib_pattern_scan_all("server", "48 89 5C 24 ?", my_callback, &count);
/// if (result == 0) {
///     printf("Found %d matches\n", count);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_pattern_scan_all(
    binary_name: *const c_char,
    pattern: *const c_char,
    callback: PatternScanCallback,
    user_data: *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || pattern.is_null() {
            return_error!(-2, "invalid parameters: binary_name or pattern is null");
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let pattern_str = match CStr::from_ptr(pattern).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.pattern_scan_all(binary_name_str, pattern_str, |index, addr| {
            // Call the C callback function
            callback(index, addr as *mut c_void, user_data)
        }) {
            Ok(_) => 0,
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find an exported symbol by name and return its relative virtual address
///
/// Searches for an exported symbol in the binary's export table and returns
/// its relative virtual address (RVA). This works for PE exports on Windows.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (null-terminated C string)
/// * `export_name` - Export name to search for (null-terminated C string)
/// * `result` - Pointer to store the resulting relative virtual address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary
/// * -4 if export not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* export_rva;
/// int result = s2binlib_find_export_rva("server", "CreateInterface", &export_rva);
/// if (result == 0) {
///     printf("Export RVA: %p\n", export_rva);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_export_rva(
    binary_name: *const c_char,
    export_name: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || export_name.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, export_name or result is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let export_name_str = match CStr::from_ptr(export_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.find_export_rva(binary_name_str, export_name_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find an exported symbol by name and return its runtime memory address
///
/// Searches for an exported symbol and returns its runtime memory address,
/// adjusted for the module's base address in the running process.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (null-terminated C string)
/// * `export_name` - Export name to search for (null-terminated C string)
/// * `result` - Pointer to store the resulting memory address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary or get base address
/// * -4 if export not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* export_addr;
/// int result = s2binlib_find_export("server", "CreateInterface", &export_addr);
/// if (result == 0) {
///     printf("Export at: %p\n", export_addr);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_export(
    binary_name: *const c_char,
    export_name: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || export_name.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, export_name or result is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let export_name_str = match CStr::from_ptr(export_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.find_export(binary_name_str, export_name_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find a symbol by name and return its relative virtual address
///
/// Searches for a symbol in the binary's dynamic symbol table and returns
/// its relative virtual address (RVA). This works for ELF dynamic symbols on Linux.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (null-terminated C string)
/// * `symbol_name` - Symbol name to search for (null-terminated C string)
/// * `result` - Pointer to store the resulting relative virtual address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if symbol not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* symbol_rva;
/// int result = s2binlib_find_symbol_rva("server", "_Z13CreateInterfacev", &symbol_rva);
/// if (result == 0) {
///     printf("Symbol RVA: %p\n", symbol_rva);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_symbol_rva(
    binary_name: *const c_char,
    symbol_name: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || symbol_name.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, symbol_name or result is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let symbol_name_str = match CStr::from_ptr(symbol_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.find_symbol_rva(binary_name_str, symbol_name_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-3, "Failed to load binary or operation failed"),
        }
    }
}

/// Read bytes from binary at a file offset
///
/// Reads raw bytes from the binary file at the specified file offset into the provided buffer.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to read from (null-terminated C string)
/// * `file_offset` - File offset to read from
/// * `buffer` - Buffer to store the read bytes
/// * `buffer_size` - Size of the buffer (number of bytes to read)
///
/// # Returns
/// * 0 on success (bytes written to buffer)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to read
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// uint8_t buffer[16];
/// int result = s2binlib_read_by_file_offset("server", 0x1000, buffer, sizeof(buffer));
/// if (result == 0) {
///     // Use buffer
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_read_by_file_offset(
    binary_name: *const c_char,
    file_offset: u64,
    buffer: *mut u8,
    buffer_size: usize,
) -> i32 {
    unsafe {
        if binary_name.is_null() || buffer.is_null() || buffer_size == 0 {
            return -2;
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.read_by_file_offset(binary_name_str, file_offset, buffer_size) {
            Ok(bytes) => {
                let copy_size = bytes.len().min(buffer_size);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, copy_size);
                0
            }
            Err(_) => return_error!(-3, "Failed to load binary or operation failed"),
        }
    }
}

/// Read bytes from binary at a relative virtual address
///
/// Reads raw bytes from the binary at the specified relative virtual address (RVA) into the provided buffer.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to read from (null-terminated C string)
/// * `rva` - Virtual address to read from
/// * `buffer` - Buffer to store the read bytes
/// * `buffer_size` - Size of the buffer (number of bytes to read)
///
/// # Returns
/// * 0 on success (bytes written to buffer)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to read
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// uint8_t buffer[16];
/// int result = s2binlib_read_by_rva("server", 0x140001000, buffer, sizeof(buffer));
/// if (result == 0) {
///     // Use buffer
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_read_by_rva(
    binary_name: *const c_char,
    rva: u64,
    buffer: *mut u8,
    buffer_size: usize,
) -> i32 {
    unsafe {
        if binary_name.is_null() || buffer.is_null() || buffer_size == 0 {
            return -2;
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.read_by_rva(binary_name_str, rva, buffer_size) {
            Ok(bytes) => {
                let copy_size = bytes.len().min(buffer_size);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, copy_size);
                0
            }
            Err(_) => return_error!(-3, "Failed to load binary or operation failed"),
        }
    }
}

/// Read bytes from binary at a runtime memory address
///
/// Reads raw bytes from the binary at the specified runtime memory address into the provided buffer.
/// The address is automatically converted to a relative virtual address.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to read from (null-terminated C string)
/// * `mem_address` - Runtime memory address to read from
/// * `buffer` - Buffer to store the read bytes
/// * `buffer_size` - Size of the buffer (number of bytes to read)
///
/// # Returns
/// * 0 on success (bytes written to buffer)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to read
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// uint8_t buffer[16];
/// int result = s2binlib_read_by_mem_address("server", mem_addr, buffer, sizeof(buffer));
/// if (result == 0) {
///     // Use buffer
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_read_by_mem_address(
    binary_name: *const c_char,
    mem_address: u64,
    buffer: *mut u8,
    buffer_size: usize,
) -> i32 {
    unsafe {
        if binary_name.is_null() || buffer.is_null() || buffer_size == 0 {
            return -2;
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.read_by_mem_address(binary_name_str, mem_address, buffer_size) {
            Ok(bytes) => {
                let copy_size = bytes.len().min(buffer_size);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, copy_size);
                0
            }
            Err(_) => return_error!(-3, "Failed to load binary or operation failed"),
        }
    }
}

/// Find a virtual function by vtable name and index, return relative virtual address
///
/// Locates a vtable by its class name, then reads the virtual function pointer
/// at the specified index. Returns the relative virtual address of the function.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (null-terminated C string)
/// * `vtable_name` - Class name whose vtable to search for (null-terminated C string)
/// * `vfunc_index` - Index of the virtual function in the vtable (0-based)
/// * `result` - Pointer to store the resulting relative virtual address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary
/// * -4 if vtable or vfunc not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* vfunc_rva;
/// int result = s2binlib_find_vfunc_by_vtbname_rva("server", "CBaseEntity", 5, &vfunc_rva);
/// if (result == 0) {
///     printf("VFunc RVA: %p\n", vfunc_rva);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_vfunc_by_vtbname_rva(
    binary_name: *const c_char,
    vtable_name: *const c_char,
    vfunc_index: usize,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || vtable_name.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, vtable_name or result is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let vtable_name_str = match CStr::from_ptr(vtable_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.find_vfunc_by_vtbname_rva(binary_name_str, vtable_name_str, vfunc_index) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find a virtual function by vtable name and index, return runtime address
///
/// Locates a vtable by its class name, then reads the virtual function pointer
/// at the specified index. Returns the runtime memory address of the function.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (null-terminated C string)
/// * `vtable_name` - Class name whose vtable to search for (null-terminated C string)
/// * `vfunc_index` - Index of the virtual function in the vtable (0-based)
/// * `result` - Pointer to store the resulting memory address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary or get base address
/// * -4 if vtable or vfunc not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* vfunc_addr;
/// int result = s2binlib_find_vfunc_by_vtbname("server", "CBaseEntity", 5, &vfunc_addr);
/// if (result == 0) {
///     printf("VFunc at: %p\n", vfunc_addr);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_vfunc_by_vtbname(
    binary_name: *const c_char,
    vtable_name: *const c_char,
    vfunc_index: usize,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || vtable_name.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, vtable_name or result is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let vtable_name_str = match CStr::from_ptr(vtable_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.find_vfunc_by_vtbname(binary_name_str, vtable_name_str, vfunc_index) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find a virtual function by vtable pointer and index, return relative virtual address
///
/// Given a runtime pointer to a vtable, reads the virtual function pointer
/// at the specified index. Returns the relative virtual address of the function.
/// The appropriate binary is automatically detected from the vtable pointer.
///
/// # Parameters
/// * `vtable_ptr` - Runtime pointer to the vtable
/// * `vfunc_index` - Index of the virtual function in the vtable (0-based)
/// * `result` - Pointer to store the resulting relative virtual address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if binary not found for pointer
/// * -4 if failed to read vfunc
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* vfunc_rva;
/// int result = s2binlib_find_vfunc_by_vtbptr_rva(vtable_ptr, 5, &vfunc_rva);
/// if (result == 0) {
///     printf("VFunc RVA: %p\n", vfunc_rva);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_vfunc_by_vtbptr_rva(
    vtable_ptr: *mut c_void,
    vfunc_index: usize,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if result.is_null() {
            return_error!(-2, "invalid parameter: result pointer is null");
        }

        let s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_ref() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        match s2binlib.find_vfunc_by_vtbptr_rva(vtable_ptr as u64, vfunc_index) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find a virtual function by vtable pointer and index, return runtime address
///
/// Given a runtime pointer to a vtable, reads the virtual function pointer
/// at the specified index. Returns the runtime memory address of the function.
/// The appropriate binary is automatically detected from the vtable pointer.
///
/// # Parameters
/// * `vtable_ptr` - Runtime pointer to the vtable
/// * `vfunc_index` - Index of the virtual function in the vtable (0-based)
/// * `result` - Pointer to store the resulting memory address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if binary not found for pointer
/// * -4 if failed to read vfunc
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* vfunc_addr;
/// int result = s2binlib_find_vfunc_by_vtbptr(vtable_ptr, 5, &vfunc_addr);
/// if (result == 0) {
///     printf("VFunc at: %p\n", vfunc_addr);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_vfunc_by_vtbptr(
    vtable_ptr: *mut c_void,
    vfunc_index: usize,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if result.is_null() {
            return_error!(-2, "invalid parameter: result pointer is null");
        }

        let s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_ref() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        match s2binlib.find_vfunc_by_vtbptr(vtable_ptr as u64, vfunc_index) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find a string in the binary and return its relative virtual address
///
/// Searches for an exact string match in the binary and returns its relative virtual address.
/// The string must match exactly (case-sensitive).
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (null-terminated C string)
/// * `string` - String to search for (null-terminated C string)
/// * `result` - Pointer to store the resulting relative virtual address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary
/// * -4 if string not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* string_rva;
/// int result = s2binlib_find_string_rva("server", "CBaseEntity", &string_rva);
/// if (result == 0) {
///     printf("String RVA: %p\n", string_rva);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_string_rva(
    binary_name: *const c_char,
    string: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || string.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, string or result is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let string_str = match CStr::from_ptr(string).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.find_string_rva(binary_name_str, string_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find a string in the binary and return its runtime memory address
///
/// Searches for an exact string match in the binary and returns its runtime memory address.
/// The string must match exactly (case-sensitive).
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to search (null-terminated C string)
/// * `string` - String to search for (null-terminated C string)
/// * `result` - Pointer to store the resulting memory address
///
/// # Returns
/// * 0 on success (address written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary or get base address
/// * -4 if string not found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// void* string_addr;
/// int result = s2binlib_find_string("server", "CBaseEntity", &string_addr);
/// if (result == 0) {
///     printf("String at: %p\n", string_addr);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_string(
    binary_name: *const c_char,
    string: *const c_char,
    result: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || string.is_null() || result.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name, string or result is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let string_str = match CStr::from_ptr(string).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.find_string(binary_name_str, string_str) {
            Ok(addr) => {
                *result = addr as *mut c_void;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Dump and cache all cross-references in a binary
///
/// This function disassembles all executable sections of the binary once and builds
/// a complete cross-reference (xref) database. The results are cached internally and
/// can be quickly queried using s2binlib_find_xrefs_cached().
///
/// This is useful when you need to find all code locations that reference a particular
/// address. The operation may take some time for large binaries, but subsequent queries
/// are very fast.
///
/// If the binary is not yet loaded, it will be loaded automatically.
///
/// # Parameters
/// * `binary_name` - Name of the binary to analyze (null-terminated C string)
///
/// # Returns
/// * 0 on success
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary
/// * -4 if failed to dump xrefs
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// int result = s2binlib_dump_xrefs("server");
/// if (result == 0) {
///     printf("Xrefs cached successfully\n");
///     // Now you can quickly query xrefs
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_dump_xrefs(binary_name: *const c_char) -> i32 {
    unsafe {
        if binary_name.is_null() {
            return_error!(-2, "invalid parameter: binary_name is null");
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.dump_xrefs(binary_name_str) {
            Ok(_) => 0,
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Get the count of cached cross-references for a target relative virtual address
///
/// Returns the number of code locations that reference the specified target address.
/// The binary must have been analyzed with s2binlib_dump_xrefs() first.
///
/// Use this function to determine the buffer size needed for s2binlib_get_xrefs_cached().
///
/// # Parameters
/// * `binary_name` - Name of the binary (null-terminated C string)
/// * `target_rva` - The target relative virtual address to find references to
///
/// # Returns
/// * Non-negative: Number of xrefs found
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if binary not analyzed (call s2binlib_dump_xrefs first)
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// // First, dump xrefs
/// s2binlib_dump_xrefs("server");
///
/// // Get xref count
/// int count = s2binlib_get_xrefs_count("server", (void*)0x140001000);
/// if (count > 0) {
///     void** xrefs = malloc(count * sizeof(void*));
///     s2binlib_get_xrefs_cached("server", (void*)0x140001000, xrefs, count);
///     // Use xrefs
///     free(xrefs);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_get_xrefs_count(
    binary_name: *const c_char,
    target_rva: *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() {
            return_error!(-2, "invalid parameter: binary_name is null");
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_ref() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        match s2binlib.find_xrefs_cached(binary_name_str, target_rva as u64) {
            Some(xrefs) => xrefs.len() as i32,
            None => -3,
        }
    }
}

/// Get cached cross-references for a target relative virtual address into a buffer
///
/// Returns all code locations (relative virtual addresses) that reference the specified target address
/// into the provided buffer. The binary must have been analyzed with s2binlib_dump_xrefs() first.
///
/// Use s2binlib_get_xrefs_count() to determine the required buffer size.
///
/// # Parameters
/// * `binary_name` - Name of the binary (null-terminated C string)
/// * `target_rva` - The target relative virtual address to find references to
/// * `buffer` - Buffer to store the xref addresses (array of uint64_t)
/// * `buffer_size` - Size of the buffer (number of uint64_t elements it can hold)
///
/// # Returns
/// * Non-negative: Number of xrefs written to buffer
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if binary not analyzed (call s2binlib_dump_xrefs first)
/// * -4 if buffer too small
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// // First, dump xrefs
/// s2binlib_dump_xrefs("server");
///
/// // Get xref count
/// int count = s2binlib_get_xrefs_count("server", (void*)0x140001000);
/// if (count > 0) {
///     void** xrefs = malloc(count * sizeof(void*));
///     int result = s2binlib_get_xrefs_cached("server", (void*)0x140001000, xrefs, count);
///     if (result > 0) {
///         for (int i = 0; i < result; i++) {
///             printf("Xref at: %p\n", xrefs[i]);
///         }
///     }
///     free(xrefs);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_get_xrefs_cached(
    binary_name: *const c_char,
    target_rva: *mut c_void,
    buffer: *mut *mut c_void,
    buffer_size: usize,
) -> i32 {
    unsafe {
        if binary_name.is_null() || buffer.is_null() || buffer_size == 0 {
            return -2;
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_ref() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        match s2binlib.find_xrefs_cached(binary_name_str, target_rva as u64) {
            Some(xrefs) => {
                if xrefs.len() * std::mem::size_of::<*mut c_void>() > buffer_size {
                    return -4; // Buffer too small
                }

                let copy_count = xrefs.len();
                for (i, addr) in xrefs.iter().enumerate() {
                    *buffer.add(i) = *addr as *mut c_void;
                }
                copy_count as i32
            }
            None => -3,
        }
    }
}

/// Unload a specific binary from memory
///
/// Removes the specified binary from the internal cache, freeing up memory.
/// This is useful when you no longer need a particular binary.
///
/// # Parameters
/// * `binary_name` - Name of the binary to unload (e.g., "server", "client") (null-terminated C string)
///
/// # Returns
/// * 0 on success
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -5 if internal error (mutex lock failed)
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
/// The caller must ensure that the pointer is valid and points to a null-terminated C string.
///
/// # Example
/// ```c
/// int result = s2binlib_unload_binary("server");
/// if (result == 0) {
///     printf("Binary unloaded successfully\n");
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_unload_binary(binary_name: *const c_char) -> i32 {
    unsafe {
        if binary_name.is_null() {
            return_error!(-2, "invalid parameter: binary_name is null");
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        s2binlib.unload_binary(binary_name_str);
        0
    }
}

/// Unload all binaries from memory
///
/// Removes all loaded binaries from the internal cache, freeing up memory.
/// This is useful for cleanup operations or when you need to start fresh.
///
/// # Returns
/// * 0 on success
/// * -1 if S2BinLib not initialized
/// * -5 if internal error (mutex lock failed)
///
/// # Safety
/// This function is safe to call at any time after initialization.
///
/// # Example
/// ```c
/// int result = s2binlib_unload_all_binaries();
/// if (result == 0) {
///     printf("All binaries unloaded successfully\n");
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_unload_all_binaries() -> i32 {
    let mut s2binlib_guard = match S2BINLIB.lock() {
        Ok(guard) => guard,
        Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
    };

    let s2binlib = match s2binlib_guard.as_mut() {
        Some(lib) => lib,
        None => return_error!(-1, "S2BinLib not initialized"),
    };

    s2binlib.unload_all_binaries();
    0
}

/// Install a JIT trampoline at a memory address
///
/// Creates a JIT trampoline that can be used to hook or intercept function calls.
/// This function reads the original function pointer at the specified memory address,
/// creates a trampoline, and replaces the original pointer with the trampoline address.
///
/// If a trampoline is already installed at the same address, this function does nothing
/// and returns success.
///
/// # Parameters
/// * `mem_address` - Runtime memory address where to install the trampoline
///
/// # Returns
/// * 0 on success
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to install trampoline
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it:
/// - Dereferences raw pointers
/// - Modifies memory at the specified address
/// - Changes memory protection flags
///
/// The caller must ensure that:
/// - The memory address is valid and writable
/// - The address points to an 8-byte function pointer
/// - No other threads are accessing the memory during the operation
///
/// # Example
/// ```c
/// void* vtable_ptr = ...; // Get vtable pointer
/// void* trampoline_address;
/// int result = s2binlib_install_trampoline(vtable_ptr, &trampoline_address);
/// if (result == 0) {
///     printf("Trampoline installed successfully\n");
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_install_trampoline(
    mem_address: *mut c_void,
    trampoline_address_out: *mut *mut c_void,
) -> i32 {
    let mut s2binlib_guard = match S2BINLIB.lock() {
        Ok(guard) => guard,
        Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
    };

    let s2binlib = match s2binlib_guard.as_mut() {
        Some(lib) => lib,
        None => return_error!(-1, "S2BinLib not initialized"),
    };

    match s2binlib.install_trampoline(mem_address as u64) {
        Ok(address) => {
            unsafe {
                *trampoline_address_out = address as *mut c_void;
            }
            0
        }
        Err(_) => return_error!(-3, "Failed to install trampoline"),
    }
}

/// Follow cross-reference from memory address to memory address
///
/// This function reads the instruction at the given memory address,
/// decodes it using iced-x86, and returns the target address if the
/// instruction contains a valid cross-reference.
///
/// valid xrefs include:
/// - RIP-relative memory operands (e.g., lea rax, [rip+0x1000])
/// - Near branches (call, jmp, jcc)
/// - Absolute memory operands
///
/// # Parameters
/// * `mem_address` - Runtime memory address to analyze
/// * `target_address_out` - Pointer to store the target address
///
/// # Returns
/// * 0 on success (target address written to target_address_out)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if no valid xref found or invalid instruction
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it:
/// - Dereferences raw pointers
/// - Reads memory at the specified address
///
/// The caller must ensure that:
/// - The memory address is valid and readable
/// - The address points to executable code
///
/// # Example
/// ```c
/// void* instruction_addr = ...; // Address of an instruction
/// void* target_addr;
/// int result = s2binlib_follow_xref_mem_to_mem(instruction_addr, &target_addr);
/// if (result == 0) {
///     printf("Xref target: %p\n", target_addr);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_follow_xref_mem_to_mem(
    mem_address: *const c_void,
    target_address_out: *mut *mut c_void,
) -> i32 {
    if mem_address.is_null() || target_address_out.is_null() {
        return_error!(
            -2,
            "invalid parameters: mem_address or target_address_out is null"
        );
    }

    let s2binlib_guard = match S2BINLIB.lock() {
        Ok(guard) => guard,
        Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
    };

    let s2binlib = match s2binlib_guard.as_ref() {
        Some(lib) => lib,
        None => return_error!(-1, "S2BinLib not initialized"),
    };

    match s2binlib.follow_xref_mem_to_mem(mem_address as u64) {
        Ok(target) => {
            unsafe {
                *target_address_out = target as *mut c_void;
            }
            0
        }
        Err(_) => return_error!(-3, "No valid xref found or invalid instruction"),
    }
}

/// Follow cross-reference from relative virtual address to memory address
///
/// This function reads the instruction at the given relative virtual address from the file,
/// decodes it using iced-x86, and returns the target memory address if the
/// instruction contains a valid cross-reference.
///
/// valid xrefs include:
/// - RIP-relative memory operands (e.g., lea rax, [rip+0x1000])
/// - Near branches (call, jmp, jcc)
/// - Absolute memory operands
///
/// # Parameters
/// * `binary_name` - Name of the binary (null-terminated C string)
/// * `rva` - Virtual address to analyze
/// * `target_address_out` - Pointer to store the target memory address
///
/// # Returns
/// * 0 on success (target address written to target_address_out)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary or no valid xref found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
/// The caller must ensure that the pointers are valid.
///
/// # Example
/// ```c
/// void* target_addr;
/// int result = s2binlib_follow_xref_rva_to_mem("server", 0x140001000, &target_addr);
/// if (result == 0) {
///     printf("Xref target: %p\n", target_addr);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_follow_xref_rva_to_mem(
    binary_name: *const c_char,
    rva: u64,
    target_address_out: *mut *mut c_void,
) -> i32 {
    unsafe {
        if binary_name.is_null() || target_address_out.is_null() {
            return_error!(
                -2,
                "invalid parameters: binary_name or target_address_out is null"
            );
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.follow_xref_rva_to_mem(binary_name_str, rva) {
            Ok(target) => {
                *target_address_out = target as *mut c_void;
                0
            }
            Err(_) => return_error!(-3, "Failed to load binary or operation failed"),
        }
    }
}

/// Follow cross-reference from relative virtual address to relative virtual address
///
/// This function reads the instruction at the given relative virtual address from the file,
/// decodes it using iced-x86, and returns the target relative virtual address if the
/// instruction contains a valid cross-reference.
///
/// valid xrefs include:
/// - RIP-relative memory operands (e.g., lea rax, [rip+0x1000])
/// - Near branches (call, jmp, jcc)
/// - Absolute memory operands
///
/// # Parameters
/// * `binary_name` - Name of the binary (null-terminated C string)
/// * `rva` - Virtual address to analyze
/// * `target_rva_out` - Pointer to store the target relative virtual address
///
/// # Returns
/// * 0 on success (target RVA written to target_rva_out)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if failed to load binary or no valid xref found
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
/// The caller must ensure that the pointers are valid.
///
/// # Example
/// ```c
/// uint64_t target_rva;
/// int result = s2binlib_follow_xref_rva_to_rva("server", 0x140001000, &target_rva);
/// if (result == 0) {
///     printf("Xref target RVA: 0x%llX\n", target_rva);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_follow_xref_rva_to_rva(
    binary_name: *const c_char,
    rva: u64,
    target_rva_out: *mut u64,
) -> i32 {
    unsafe {
        if binary_name.is_null() || target_rva_out.is_null() {
            return -2;
        }

        let binary_name_str = match CStr::from_ptr(binary_name).to_str() {
            Ok(s) => s,
            Err(_) => return_error!(-2, "Failed to convert C string to UTF-8"),
        };

        let mut s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_mut() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        if !s2binlib.is_binary_loaded(binary_name_str) {
            s2binlib.load_binary(binary_name_str);
        }

        match s2binlib.follow_xref_rva_to_rva(binary_name_str, rva) {
            Ok(target) => {
                *target_rva_out = target;
                0
            }
            Err(_) => return_error!(-3, "Failed to load binary or operation failed"),
        }
    }
}

/// Find the NetworkVar_StateChanged vtable index by relative virtual address
///
/// This function scans the vtable at the given relative virtual address to find the
/// index of the NetworkVar_StateChanged virtual function. It analyzes each
/// virtual function in the vtable looking for the specific instruction pattern
/// that identifies the StateChanged function (cmp dword ptr [reg+56], 0xFF).
///
/// # Parameters
/// * `vtable_rva` - Virtual address of the vtable to analyze
/// * `result` - Pointer to store the resulting index (as u64)
///
/// # Returns
/// * 0 on success (index written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -4 if NetworkVar_StateChanged not found in vtable
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// uint64_t index;
/// int result = s2binlib_find_networkrvar_vtable_statechanged_rva(0x140001000, &index);
/// if (result == 0) {
///     printf("StateChanged index: %llu\n", index);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_networkrvar_vtable_statechanged_rva(
    vtable_rva: u64,
    result: *mut u64,
) -> i32 {
    unsafe {
        if result.is_null() {
            return_error!(-2, "invalid parameter: result pointer is null");
        }

        let s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_ref() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        match s2binlib.find_networkrvar_vtable_statechanged_rva(vtable_rva) {
            Ok(index) => {
                *result = index;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}

/// Find the NetworkVar_StateChanged vtable index by memory address
///
/// This function converts the runtime memory address to a relative virtual address,
/// then scans the vtable to find the index of the NetworkVar_StateChanged
/// virtual function. It analyzes each virtual function in the vtable looking
/// for the specific instruction pattern that identifies the StateChanged function.
///
/// # Parameters
/// * `vtable_mem_address` - Runtime memory address of the vtable
/// * `result` - Pointer to store the resulting index (as u64)
///
/// # Returns
/// * 0 on success (index written to result)
/// * -1 if S2BinLib not initialized
/// * -2 if invalid parameters
/// * -3 if address conversion failed
/// * -4 if NetworkVar_StateChanged not found in vtable
/// * -5 if internal error
///
/// # Safety
/// This function is unsafe because it dereferences raw pointers.
///
/// # Example
/// ```c
/// uint64_t index;
/// int result = s2binlib_find_networkrvar_vtable_statechanged(vtable_ptr, &index);
/// if (result == 0) {
///     printf("StateChanged index: %llu\n", index);
/// }
/// ```
#[unsafe(no_mangle)]
pub extern "C" fn s2binlib_find_networkrvar_vtable_statechanged(
    vtable_mem_address: u64,
    result: *mut u64,
) -> i32 {
    unsafe {
        if result.is_null() {
            return_error!(-2, "invalid parameter: result pointer is null");
        }

        let s2binlib_guard = match S2BINLIB.lock() {
            Ok(guard) => guard,
            Err(_) => return_error!(-5, "Failed to acquire global S2BinLib lock"),
        };

        let s2binlib = match s2binlib_guard.as_ref() {
            Some(lib) => lib,
            None => return_error!(-1, "S2BinLib not initialized"),
        };

        match s2binlib.find_networkrvar_vtable_statechanged(vtable_mem_address) {
            Ok(index) => {
                *result = index;
                0
            }
            Err(_) => return_error!(-4, "Pattern not found or operation failed"),
        }
    }
}
