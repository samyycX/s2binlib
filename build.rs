fn main() {
    #[cfg(target_os = "windows")]
    {
      unsafe { std::env::set_var("CARGO_CFG_TARGET_FEATURE", "crt-static") };
      let use_static_crt = {
        let target_features = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or(String::new());
        target_features.split(",").any(|f| f == "crt-static")
      };

      if use_static_crt {
        println!("cargo:warning=Using static CRT");
      } else {
        println!("cargo:warning=Using dynamic CRT");
      }

    }
}