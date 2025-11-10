use std::fs::{self, File};
use std::io::Write;

use anyhow::Result;
use s2binlib::S2BinLib;


pub fn dump_diff(s2binlib: &S2BinLib, dump_dir: &str, binary_name: &str, base_class: &str) -> Result<()> {

  fs::create_dir_all(format!("{}/vtable_diff/{}", dump_dir, binary_name))?;
  let dump_file = format!("{}/vtable_diff/{}/{}.txt", dump_dir, binary_name, base_class);

  let vtables = s2binlib.get_vtables(binary_name)?;
  let base_info = vtables.iter().find(|vtable| vtable.type_name.eq(base_class)).unwrap();
  let base_count = base_info.methods.len();
  let mut file = File::create(dump_file)?;

  let mut diffs = vec![0; base_count];
  let mut children = 0;

  for vtable in vtables {
    if vtable.bases.iter().any(|base| base.type_name.contains(base_class)) {
      if vtable.methods.len() < base_count {
        continue; // multiple hierarchy vtable
      }
      children += 1;

      for i in 0..vtable.methods.len() {
        if i < base_info.methods.len() {
          let method = vtable.methods[i];
          let base_method = base_info.methods[i];
          if method != base_method {
            diffs[i] += 1;
          }
        }
      }
    }
  }

  writeln!(file, "Base: {}", base_class)?;
  writeln!(file, "Virtual Function Count: {}", base_count)?;
  writeln!(file, "Children Count: {}", children)?;
  writeln!(file, "=============================================")?;
  for i in 0..diffs.len() {
    writeln!(file, "{:<10} [DIFF {}]", format!("func_{}", i), diffs[i])?;
  }
  file.flush()?;

  Ok(())
}
