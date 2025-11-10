use std::fs;

use anyhow::Result;
use log::info;
use s2binlib::{S2BinLib, VTableInfo};
use stringvec::stringvec;

mod dumpers {
    pub mod gamesystem_dumper;
    pub mod vtable_dumper;
    pub mod networkvar_dumper;
    pub mod entity_dumper;
    pub mod diff_dumper;
}

fn main() -> Result<()> {

    let mut s2binlib = S2BinLib::new("F:/cs2server/game", "csgo", "windows");

    tracing_subscriber::fmt::init();
    let tracked_binaries = stringvec![
        "server",
        "engine2",
        "tier0",
        "client",
        "networksystem",
        "soundsystem",
        "pulse_system",
    ];


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

    dumpers::diff_dumper::dump_diff(&s2binlib, &dump_dir, "server", "CBaseEntity")?;
    dumpers::diff_dumper::dump_diff(&s2binlib, &dump_dir, "server", "CBaseModelEntity")?;
    dumpers::diff_dumper::dump_diff(&s2binlib, &dump_dir, "server", "CCSWeaponBase")?;
    dumpers::diff_dumper::dump_diff(&s2binlib, &dump_dir, "server", "IGameSystem")?;
    dumpers::diff_dumper::dump_diff(&s2binlib, &dump_dir, "server", "CTraceFilter")?;
    dumpers::diff_dumper::dump_diff(&s2binlib, &dump_dir, "server", "CRecipientFilter")?;
    dumpers::diff_dumper::dump_diff(&s2binlib, &dump_dir, "client", "C_BaseEntity")?;
    dumpers::diff_dumper::dump_diff(&s2binlib, &dump_dir, "client", "C_BaseModelEntity")?;
    dumpers::diff_dumper::dump_diff(&s2binlib, &dump_dir, "client", "C_CSWeaponBase")?;
    dumpers::diff_dumper::dump_diff(&s2binlib, &dump_dir, "client", "IGameSystem")?;
    dumpers::entity_dumper::dump_entities_server(&s2binlib, &dump_dir)?;
    dumpers::entity_dumper::dump_entities_client(&s2binlib, &dump_dir)?;
    dumpers::gamesystem_dumper::dump_gamesystems(&s2binlib, &dump_dir, "server")?;
    dumpers::gamesystem_dumper::dump_gamesystems(&s2binlib, &dump_dir, "client")?;
    dumpers::vtable_dumper::dump_vtables(&s2binlib, &tracked_binaries, &dump_dir)?;
    dumpers::networkvar_dumper::dump_networkvars(&s2binlib, &dump_dir)?;

    Ok(())
}