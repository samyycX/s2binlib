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

mod flags;
pub mod jit;
mod memory;
mod pattern;
mod s2binlib;
mod vtable;
mod module;
mod view;

pub use flags::*;
pub use pattern::*;
pub use s2binlib::*;
pub use vtable::*;

use libloading;

#[cfg(test)]
#[allow(unused_imports, unused_variables)]
mod tests {
    use std::{
        fs::{self, File},
        io::{BufWriter, Write},
        time::Instant,
    };

    use anyhow::Result;
    use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, OpKind};
    use libloading::Library;
    use object::BinaryFormat;

    use crate::{module::get_module_info, view::{BinaryView, FileBinaryView, MemoryView}};

    use super::*;

    #[test]
    fn test_s2binlib() -> Result<()> {
        // fs::write("funcs.txt", serde_json::to_string_pretty(&funcs)?)?;

        let start = Instant::now();

        let mut s2binlib = S2BinLib::new("F:/cs2server/game", "csgo", "windows");

        s2binlib.load_binary("server");

        println!("lib: {:?}", "");
        let lib = unsafe { Library::new("F:/cs2server/game/bin/win64/tier0.dll")? };

        println!("lib: {:?}", lib);

        let module_info = get_module_info("tier0.dll")?;

        let view = unsafe {MemoryView::new(
            module_info.base_address as *const u8,
            module_info.size,
            module_info.base_address as u64,
            BinaryFormat::Pe,
        ) };

        let view2 = s2binlib.get_file_binary_view("server")?;

        let mut parser = MsvcParser::new(&view);
        let vtables = parser.parse()?;

        println!("{:?}", vtables);


        // let c = view.read::<u64>(module_info.base_address as u64).unwrap();
        // let locator = parser.parse_locator(c).unwrap();
        // let vtable = parser.build_vtable_info(0x1811330D0, &locator).unwrap();

        // println!("vtables: {:?}", vtables);

        // let xref = s2binlib.pattern_scan_va("server", "4C 8D 35 ? ? ? ? 77")?;

        // let duration = start.elapsed();
        // println!("Time taken: {:?}", duration);
        // println!("xref {:X}", xref);
        // println!("follow xref {:X}", s2binlib.follow_xref_va_to_va("server", xref)?);

        // let str = s2binlib.find_string_va("server", "Think_Update")?;
        // println!("str: {:X}", str);
        // s2binlib.dump_xrefs("server")?;
        // // println!("{:X}", s2binlib.find_export_va("tier0", "Plat_GetOSType")?);
        // println!("{:X}", s2binlib.find_vfunc_by_vtbname_va("server", "CCSPlayerController", 11)?);

        Ok(())
    }
}
