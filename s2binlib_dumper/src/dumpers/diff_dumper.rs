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
    writeln!(file, "{:<10} [ DIFF {:<3} ]", format!("func_{}", i), diffs[i])?;
  }
  file.flush()?;

  Ok(())
}
