use std::{collections::{BTreeMap, HashMap}, fs::{self, File}, io::Write};

use anyhow::Result;
use s2binlib::S2BinLib;

pub fn dump_vtables(s2binlib: &S2BinLib, tracked_binaries: &[String], dump_dir: &str) -> Result<()> {

  for binary in tracked_binaries {
    let vtables = s2binlib.get_vtables(binary)?;
    fs::create_dir_all(format!("{}/vtables", dump_dir))?;
    let file = File::create(format!("{}/vtables/{}.txt", dump_dir, binary))?;
    serde_json::to_writer_pretty(file, &vtables)?;

    let mut file = File::create(format!("{}/vtables/{}_short.txt", dump_dir, binary))?;

    let mut map: BTreeMap<String, Vec<usize>> = BTreeMap::new();

    for vtable in vtables {
      if map.contains_key(&vtable.type_name) {
        map.get_mut(&vtable.type_name).unwrap().push(vtable.methods.len());
      } else {
        map.insert(vtable.type_name.clone(), vec![vtable.methods.len()]);
      }
    }

    for (type_name, methods_len) in map {
      write!(file, "{:<50}", type_name)?;
      for method_len in methods_len {
        write!(file, " [{}]", method_len)?;
      }
      writeln!(file)?;
    }
    file.flush()?;
  }

  Ok(())
}
