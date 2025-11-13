use std::ffi::CStr;
use std::ffi::{c_char, c_void};

use crate::compat::s2binlib001::s2binlib001_create;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn CreateInterface(name: *const c_char) -> *mut c_void {
    if name.is_null() {
        return std::ptr::null_mut();
    }

    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    match name_str {
        "S2BINLIB001" => s2binlib001_create(),
        _ => std::ptr::null_mut(),
    }
}
