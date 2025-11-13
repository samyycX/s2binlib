use std::{fs::{self, File}, io::Write};

use anyhow::Result;
use log::info;
use s2binlib::S2BinLib;

pub fn dump_strings(s2binlib: &S2BinLib, dump_dir: &str, tracked_binaries: &[String]) -> Result<()> {
    fs::create_dir_all(format!("{}/strings", dump_dir))?;
    for binary in tracked_binaries {
        info!("Dumping strings for {}", binary);
        let mut file = File::create(format!("{}/strings/{}.txt", dump_dir, binary))?;
        let strings = s2binlib.get_strings(binary).unwrap();
        let mut sorted_strings = strings.keys().collect::<Vec<_>>();
        sorted_strings.sort();
        for string in sorted_strings {
            writeln!(file, "{}", string)?;
        }
        file.flush()?;
    }
    Ok(())
}