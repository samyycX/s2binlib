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