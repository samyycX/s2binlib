use anyhow::Result;
use s2binlib::S2BinLib;

fn main() -> Result<()> {

    let mut s2binlib = S2BinLib::new("F:/cs2server/game", "csgo", "windows");

    s2binlib.load_binary("server");
    s2binlib.dump_xrefs("server")?;
    s2binlib.dump_vtables("server")?;

    println!("{:X}", s2binlib.find_func_with_string_rva("server", "BuildCacheSubscribed(CEconItem)")?);
    println!("{:X}", s2binlib.find_func_with_string_rva("server", r#"Round MVP disabled: sv_nomvp is set."#)?);

    Ok(())

}
