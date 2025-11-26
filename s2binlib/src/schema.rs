use std::ffi::{CStr, c_char, c_void};

use crate::view::BinaryView;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct SchemaClassInfo {
  pub recursive_ptr: *const SchemaClassInfo,
  pub name_ptr: *const c_char,
  __unk001: [u8; 8],
  pub size: u16,
  __pad001: [u8; 2],
  pub field_count: u16,
  __pad002: [u8; 2],
  pub enums_ptr: *const SchemaFieldInfo,
  pub fields_ptr: *const SchemaFieldInfo
}

impl SchemaClassInfo {

  pub fn get_enum_info(&self, index: u16) -> Option<*const SchemaFieldInfo> {
    if index >= self.field_count {
      return None;
    }
    Some(unsafe { self.enums_ptr.add(index as usize * std::mem::size_of::<SchemaFieldInfo>()) })
  }

  pub fn get_field_info(&self, index: u16) -> Option<*const SchemaFieldInfo> {
    if index >= self.field_count {
      return None;
    }
    Some(unsafe { self.fields_ptr.add(index as usize * std::mem::size_of::<SchemaFieldInfo>()) })
  }
}

pub struct SchemaFieldInfo {
  pub name_ptr: *const c_char,
  pub type_ptr: *const SchemaTypeInfo,
  pub offset: u16,
  __pad001: [u8; 2],
  pub metadata_count: u16,
  __pad002: [u8; 2],
  pub metadata_ptr: *const c_void
}

pub struct SchemaTypeInfo {
  __unk001: [u8; 8],
  pub name_ptr: *const c_char,
}
macro_rules! impl_cstr_access {
    ($class_name:ident, $field_name:ident) => {
        impl $class_name {
            pub fn $field_name(&self) -> String {
                unsafe { 
                    let ptr = self.$field_name;
                    if ptr.is_null() {
                        String::new()
                    } else {
                        CStr::from_ptr(ptr).to_string_lossy().into_owned()
                    }
                }
            }
        }
    };
}

impl_cstr_access!(SchemaTypeInfo, name_ptr);
impl_cstr_access!(SchemaClassInfo, name_ptr);
impl_cstr_access!(SchemaFieldInfo, name_ptr);

struct SchemaParser<'a, V: BinaryView<'a>> {
  view: &'a V,
}

impl<'a, V: BinaryView<'a>> SchemaParser<'a, V> {
  pub fn new(view: &'a V) -> Self {
    Self { view }
  }
}