use std::{fs::{self, File}, io::Write};

use anyhow::Result;
use log::{info, warn};
use s2binlib::S2BinLib;

pub fn dump_networkvars(s2binlib: &S2BinLib, dump_dir: &str) -> Result<()> {
  
  let vtables = s2binlib.get_vtables("server")?;

  let mut file = File::create(format!("{}/networkvars.txt", dump_dir))?;

  for vtable in vtables {
    if vtable.type_name.contains("NetworkVar_") && !vtable.type_name.starts_with("CUtlVectorDataOps") {
      let index = s2binlib.find_networkvar_vtable_statechanged_va(vtable.vtable_address);

      if let Err(e) = index {
        warn!("Error finding statechanged index for {}: {}", vtable.type_name, e);
        continue;
      }

      info!("Dumping {}", vtable.type_name);
      let index = index.unwrap();
      let vfunc_count = vtable.methods.len();
      let statechanged_index = index as usize;
      let statechanged_func = vtable.methods[statechanged_index];
      writeln!(file, "{:<50} [{}]", vtable.type_name, vfunc_count)?;
      writeln!(file, "  StateChanged: [ {} -> {:X} ]", statechanged_index, statechanged_func)?;
    }
  }

  file.flush()?;

  Ok(())
}