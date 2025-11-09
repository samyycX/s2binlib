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
pub mod c_bindings;

pub use s2binlib::*;
pub use pattern::*;
pub use flags::*;
pub use vtable::*;

#[cfg(test)]
mod tests {
    use std::{fs::{self, File}, io::{BufWriter, Write}, time::Instant};

    use anyhow::Result;
    use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, OpKind};

    use super::*;

    #[test]
    fn test_s2binlib() -> Result<()> {
        let mut s2binlib = S2BinLib::new("F:/cs2server/game", "csgo", "windows");

        // s2binlib.load_binary("server");

        // println!("vtable count {}", s2binlib.get_vtable_vfunc_count("engine2", "CServerSideClient")?);


        // s2binlib.load_binary("tier0");
        // println!("1");

        s2binlib.load_binary("server");
        // let vtable = s2binlib.find_vtable_nested_2_va("server", "CBaseAnimGraphController", "NetworkVar_m_animGraphNetworkedVars")?;
        // let index = s2binlib.find_networkvar_vtable_statechanged_va(vtable)?;

        let res = s2binlib.dump_vtables("server")?;
        
        fs::write("vtables.txt", serde_json::to_string_pretty(&res)?)?;

        println!("{}", res.len() *std::mem::size_of::<VTableInfo>());


        let names = vec![
            "Init",                             // 0
            "PostInit",                         // 1
            "Shutdown",                         // 2
            "GameInit",                         // 3
            "GameShutdown",                     // 4
            "GamePostInit",                     // 5
            "GamePreShutdown",                  // 6
            "BuildGameSessionManifest",         // 7
            "GameActivate",                     // 8
            "ClientFullySignedOn",              // 9
            "Disconnect",                       // 10
            "unk_001",                          // 11
            "GameDeactivate",                   // 12
            "SpawnGroupPrecache",               // 13
            "SpawnGroupUncache",                // 14
            "PreSpawnGroupLoad",                // 15
            "PostSpawnGroupLoad",               // 16
            "PreSpawnGroupUnload",              // 17
            "PostSpawnGroupUnload",             // 18
            "ActiveSpawnGroupChanged",          // 19
            "ClientPostDataUpdate",             // 20
            "ClientPreRender",                  // 21
            "ClientPreEntityThink",             // 22
            "unk_101",                          // 23
            "unk_102",                          // 24
            "ClientPollNetworking",             // 25
            "unk_201",                          // 26
            "ClientUpdate",                     // 27
            "unk_301",                          // 28
            "ClientPostRender",                 // 29
            "ServerPreEntityThink",             // 30
            "ServerPostEntityThink",            // 31
            "unk_401",                          // 32
            "ServerPreClientUpdate",            // 33
            "ServerAdvanceTick",                // 34
            "ClientAdvanceTick",                // 35
            "ServerGamePostSimulate",           // 36
            "ClientGamePostSimulate",           // 37
            "ServerPostAdvanceTick",            // 38
            "ServerBeginAsyncPostTickWork",     // 39
            "unk_501",                          // 40
            "ServerEndAsyncPostTickWork",       // 41
            "ClientFrameSimulate",              // 42
            "ClientPauseSimulate",              // 43
            "ClientAdvanceNonRenderedFrame",    // 44
            "GameFrameBoundary",                // 45
            "OutOfGameFrameBoundary",           // 46
            "SaveGame",                         // 47
            "RestoreGame",                      // 48
            "unk_601",                          // 49
            "unk_602",                          // 50
            "unk_603",                          // 51
            "unk_604",                          // 52
            "unk_605",                          // 53
            "unk_606",                          // 54
            "GetName",                          // 55
            "SetGameSystemGlobalPtrs",          // 56
            "SetName",                          // 57
            "DoesGameSystemReallocate",         // 58
            "~IGameSystem",                     // 59
            "~IGameSystem2",                    // 60

            "Preserved1",
            "Preserved2",
            "Preserved3",
            "Preserved4",
            "Preserved5",
            "Preserved6",
            "Preserved7",
            "Preserved8",
            "Preserved9",
            "Preserved10",
        ];
        let max_size = names.len();

        let mut funcs = vec![vec![]; max_size];

        let size = s2binlib.get_vtable_vfunc_count("server", "IGameSystem")?;

        for vtable in res {
            for base in vtable.bases {
                if base.type_name.contains("IGameSystem") {
                    if vtable.methods.len() < size {
                        continue;
                    }
                    for i in 0..size {
                        let method = vtable.methods[i];
                        if !s2binlib.is_nullsub_va(method)? {
                            println!("{:}", vtable.type_name);
                            funcs[i].push(vtable.type_name.clone());
                        }
                    }
                }
            }
        }

        let mut file = File::create("funcs.txt")?;
        for i in 0..max_size {
            writeln!(file, "{:<35} {}", format!("{} [{}]", names[i], i), format!("{:?}", funcs[i]))?;
        }
        file.flush()?;

        // fs::write("funcs.txt", serde_json::to_string_pretty(&funcs)?)?;
        
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