use std::{fs::File, io::Write};

use anyhow::Result;
use log::info;
use s2binlib::S2BinLib;

pub fn dump_gamesystems(s2binlib: &S2BinLib, dump_dir: &str) -> Result<()> {
  
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

    let res = s2binlib.get_vtables("server")?;

    for vtable in res {
        for base in &vtable.bases {
            if base.type_name.contains("IGameSystem") {
                if vtable.methods.len() < size {
                    continue;
                }
                info!("Dumping {}", vtable.type_name);
                for i in 0..size {
                    let method = vtable.methods[i];
                    if !s2binlib.is_nullsub_va(method)? {
                        funcs[i].push(vtable.type_name.clone());
                    }
                }
            }
        }
    }

    let mut file = File::create(format!("{}/gamesystem.txt", dump_dir))?;
    for i in 0..max_size {
        writeln!(file, "{:<35} {}", format!("{} [{}]", names[i], i), format!("{:?}", funcs[i]))?;
    }
    file.flush()?;

    Ok(())
}