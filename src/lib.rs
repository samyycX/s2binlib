mod s2binlib;
mod pattern;
mod flags;
mod memory;
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
        let mut s2binlib = S2BinLib::new("F:\\cs2server\\game", "csgo", "windows");

        println!("{:X}", s2binlib.find_vtable_va("server", "CCSPlayerController")?);
        println!("{:X}", s2binlib.find_string_va("server", "Script_Trigger")?);

        let str = s2binlib.find_string_va("server", "Script_Trigger")?;
        println!("str: {}", str);
        s2binlib.dump_xrefs("server")?;
        println!("{:X?}", s2binlib.find_xrefs_cached("server", str).unwrap());
        println!("{:X}", s2binlib.find_export_va("tier0", "Plat_GetOSType")?);
        println!("{:X}", s2binlib.find_vfunc_by_vtbname_va("server", "CCSPlayerController", 11)?);

        Ok(())
    }
}