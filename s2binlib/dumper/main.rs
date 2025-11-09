use std::fs;

use anyhow::Result;
use log::info;
use s2binlib::{S2BinLib, VTableInfo};

mod dumpers {
    pub mod gamesystem_dumper;
    pub mod vtable_dumper;
    pub mod networkvar_dumper;
}

fn main() -> Result<()> {

    let mut s2binlib = S2BinLib::new("F:/cs2server/game", "csgo", "windows");

    tracing_subscriber::fmt::init();
    let tracked_binaries = vec![
        "server",
        "engine2",
        "tier0",
        "client"
    ].into_iter().map(|s| s.to_string()).collect::<Vec<_>>();


    for binary in &tracked_binaries {
        info!("Initializing {}", binary);
        s2binlib.load_binary(&binary);
        s2binlib.dump_vtables(&binary)?;
    }


    let dump_dir = format!("dump/{}", s2binlib.get_os());
    if fs::exists(&dump_dir)? {
        fs::remove_dir_all(&dump_dir)?;
    }
    fs::create_dir_all(&dump_dir)?;

    dumpers::gamesystem_dumper::dump_gamesystems(&s2binlib, &dump_dir, "server")?;
    dumpers::gamesystem_dumper::dump_gamesystems(&s2binlib, &dump_dir, "client")?;
    dumpers::vtable_dumper::dump_vtables(&s2binlib, &tracked_binaries, &dump_dir)?;
    dumpers::networkvar_dumper::dump_networkvars(&s2binlib, &dump_dir)?;

    Ok(())
}