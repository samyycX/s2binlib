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
 
mod s2binlib;
mod pattern;
mod flags;
mod memory;
mod vtable;
pub mod jit;

pub use s2binlib::*;
pub use pattern::*;
pub use flags::*;
pub use vtable::*;

#[cfg(test)]
#[allow(unused_imports, unused_variables)]
mod tests {
    use std::{fs::{self, File}, io::{BufWriter, Write}, time::Instant};

    use anyhow::Result;
    use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, OpKind};

    use super::*;

    #[test]
    fn test_s2binlib() -> Result<()> {
        

        // fs::write("funcs.txt", serde_json::to_string_pretty(&funcs)?)?;
        
        let start = Instant::now();

        let mut s2binlib = S2BinLib::new("F:/cs2server/game", "csgo", "windows");

        s2binlib.load_binary("server");

        let start = Instant::now();
        let sig = s2binlib.make_sig_va("server", 6451932160)?;
        println!("Signature: {}", sig);
        let duration = start.elapsed();
        println!("Time taken: {:?}", duration);

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