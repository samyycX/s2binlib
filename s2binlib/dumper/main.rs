use std::fs;

use anyhow::Result;
use s2binlib::{S2BinLib, VTableInfo};

mod dumpers {
    pub mod gamesystem_dumper;
    pub mod vtable_dumper;
    pub mod networkvar_dumper;
}

fn main() -> Result<()> {

  let mut s2binlib = S2BinLib::new("F:/cs2server/game", "csgo", "windows");


        let tracked_binaries = vec![
            "server",
            "engine2",
            "tier0",
        ].into_iter().map(|s| s.to_string()).collect::<Vec<_>>();

        for binary in &tracked_binaries {
            s2binlib.load_binary(&binary);
        }

        let dump_dir = format!("dump/{}", s2binlib.get_os());
        if fs::exists(&dump_dir)? {
            fs::remove_dir_all(&dump_dir)?;
        }
        fs::create_dir_all(&dump_dir)?;

        dumpers::gamesystem_dumper::dump_gamesystems(&s2binlib, &dump_dir)?;
        dumpers::vtable_dumper::dump_vtables(&s2binlib, &tracked_binaries, &dump_dir)?;
        dumpers::networkvar_dumper::dump_networkvars(&s2binlib, &dump_dir)?;

        Ok(())
    }