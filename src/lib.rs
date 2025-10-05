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
    use anyhow::Result;

    use super::*;

    #[test]
    fn test_s2binlib() -> Result<()> {
        let mut s2binlib = S2BinLib::new("/mnt/f/cs2server/game", "csgo", "linux");

        s2binlib.load_binary("server");

        // s2binlib.load_binary("tier0");
        println!("1");
        println!("{:X}", s2binlib.find_vtable_va("server", "CTraceFilter")?);
        // println!("{:X}", s2binlib.find_export("server", "CTraceFilter")?);

        let str = s2binlib.find_string_va("server", "Think_Update")?;
        println!("str: {:X}", str);
        s2binlib.dump_xrefs("server")?;
        // println!("{:X}", s2binlib.find_export_va("tier0", "Plat_GetOSType")?);
        println!("{:X}", s2binlib.find_vfunc_by_vtbname_va("server", "CCSPlayerController", 11)?);

        Ok(())
    }
}