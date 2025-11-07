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
pub mod jit;
pub mod c_bindings;

pub use s2binlib::*;
pub use pattern::*;
pub use flags::*;

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use anyhow::Result;
    use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, OpKind};

    use super::*;

    #[test]
    fn test_s2binlib() -> Result<()> {
        let mut s2binlib = S2BinLib::new("F:/cs2server/game", "csgo", "linux");

        s2binlib.load_binary("server");

        // println!("vtable count {}", s2binlib.get_vtable_vfunc_count("engine2", "CServerSideClient")?);


        // s2binlib.load_binary("tier0");
        // println!("1");


        let vtable = s2binlib.find_vtable_nested_2_va("server", "CBaseAnimGraphController", "NetworkVar_m_animGraphNetworkedVars")?;
        let index = s2binlib.find_networkvar_vtable_statechanged_va(vtable)?;
        println!("index {:X}", index);
        
        let start = Instant::now();

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