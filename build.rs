use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::collections::HashMap;

use anyhow::Result;

struct PkgConfigTemplate {
    cargo_toml: HashMap<String, String>,
    pc_in: String,
}

impl PkgConfigTemplate {
    /// Read the pkg-config template file.
    fn new<P, S>(src: P, pc_in: S) -> Result<Self>
        where P: AsRef<Path>, S: AsRef<str>
    {
        let src = src.as_ref();

        let mut pc_in_ = PathBuf::from(src);
        pc_in_.push(pc_in.as_ref());
        let pc_in = pc_in_;

        let pc_in = std::fs::read_to_string(pc_in)?;

        let cargo_toml = HashMap::from([
            ("NAME".to_string(), env!("CARGO_PKG_NAME").to_string()),
            ("DESCRIPTION".to_string(), env!("CARGO_PKG_DESCRIPTION").to_string()),
            ("VERSION".to_string(), env!("CARGO_PKG_VERSION").to_string()),
            ("HOMEPAGE".to_string(), env!("CARGO_PKG_HOMEPAGE").to_string()),
            ("REQUIRES".to_string(),
             if cfg!(feature = "crypto-botan") {
                 "botan-3"
             } else if cfg!(feature = "crypto-botan2") {
                 "botan-2"
             } else if cfg!(feature = "crypto-nettle") {
                 "nettle"
             } else if cfg!(feature = "crypto-openssl") {
                 "libssl"
             } else if cfg!(feature = "crypto-cng") {
                 ""
             } else if cfg!(feature = "crypto-rust") {
                 ""
             } else {
                 panic!("No cryptographic backend selected.  Try: \
                         \"cargo build --no-default-features \
                         --features crypto-openssl\"")
             }.to_string()),
        ]);

        Ok(PkgConfigTemplate {
            cargo_toml,
            pc_in,
        })
    }

    /// Perform substitutions on the pkg-config file based on what was
    /// read from the Cargo.toml file and the provided substitution
    /// map.
    ///
    /// The mappings in the substitution map are preferred to those in
    /// the Cargo.toml file.
    ///
    /// Substitutions take the form of keys and values where the
    /// string @KEY@ is substituted with the value of KEY.  So,
    /// @VERSION@ is substituted with the value of VERSION.
    fn substitute(&self, map: HashMap<String, String>) -> Result<String> {
        let mut pc: String = self.pc_in.clone();

        for (key, value) in map.iter().chain(self.cargo_toml.iter()) {
            pc = pc.replace(&format!("@{}@", key), value);
        }

        Ok(pc)
    }
}


fn main() -> Result<(), anyhow::Error> {
    // Generate
    // ${CARGO_TARGET_DIR}/${PROFILE}/rpm-sequoia{-uninstalled}.pc
    // from ${SRC}/rpm-sequoia.pc.in.

    let src = env::current_dir()?;

    // Location of the build directory (e.g.,
    // `/tmp/rpm-sequoia/debug`).
    let mut build_dir = PathBuf::from(&src);
    if let Some(target_dir) = env::var_os("CARGO_TARGET_DIR") {
        // Note: if CARGO_TARGET_DIR is absolute, this will first
        // clear build_dir, which is what we want.
        build_dir.push(target_dir);
    } else {
        build_dir.push("target");
    }
    let profile = env::var_os("PROFILE").expect("PROFILE not set");
    build_dir.push(&profile);


    let pc_in = PkgConfigTemplate::new(&src, "rpm-sequoia.pc.in")?;

    // Generate rpm-sequoia.pc.
    let mut pc = build_dir.clone();
    pc.push("rpm-sequoia.pc");

    let prefix = env::var_os("PREFIX");
    let prefix: &str = match prefix.as_ref().map(|s| s.to_str()) {
        Some(Some(s)) => s,
        Some(None) => Err(anyhow::anyhow!("PREFIX contains invalid UTF-8"))?,
        None => "/usr/local",
    };
    let libdir = env::var_os("LIBDIR");
    let libdir: &str = match libdir.as_ref().map(|s| s.to_str()) {
        Some(Some(s)) => s,
        Some(None) => Err(anyhow::anyhow!("LIBDIR contains invalid UTF-8"))?,
        None => "${prefix}/lib",
    };

    let content = pc_in.substitute(HashMap::from([
        ("PREFIX".to_string(), prefix.into()),
        ("LIBDIR".to_string(), libdir.into()),
    ]))?;

    let mut pc = File::create(&pc).expect(
        &format!("Creating {:?} (CARGO_TARGET_DIR: {:?})",
                 pc, env::var_os("CARGO_TARGET_DIR")));
    pc.write_all(content.as_bytes())?;


    // Generate rpm-sequoia-uninstalled.pc.
    let mut pc = build_dir.clone();
    pc.push("rpm-sequoia-uninstalled.pc");

    let content = pc_in.substitute(HashMap::from([
        ("PREFIX".to_string(),
         build_dir.to_str()
             .expect("build directory is not valid UTF-8").to_string()),
        ("LIBDIR".to_string(), "${prefix}".into()),
    ]))?;

    let mut pc = File::create(&pc).expect(
        &format!("Creating {:?} (CARGO_TARGET_DIR: {:?})",
                 pc, env::var_os("CARGO_TARGET_DIR")));
    pc.write_all(content.as_bytes())?;


    // Rerun if...
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=rpm-sequoia.pc.in");
    println!("cargo:rerun-if-env-changed=PREFIX");
    println!("cargo:rerun-if-env-changed=LIBDIR");
    println!("cargo:rerun-if-env-changed=PROFILE");
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");


    // Set the soname.
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let env = env::var("CARGO_CFG_TARGET_ENV").unwrap();

    // We do not care about `_pre` and such.
    let major = env::var("CARGO_PKG_VERSION_MAJOR").unwrap();
    let minor = env::var("CARGO_PKG_VERSION_MINOR").unwrap();
    let patch = env::var("CARGO_PKG_VERSION_PATCH").unwrap();

    // libdir might contain "${prefix}". Replace it with
    // the actual prefix value if found.
    let libdir_resolved = libdir.replace("${prefix}", prefix);

    let linker_lines = cdylib_link_lines::shared_object_link_args(
        "rpm_sequoia",
        &major, &minor, &patch, &arch, &os, &env,
        PathBuf::from(libdir_resolved), build_dir.clone(),
    );

    for line in linker_lines {
        println!("cargo:rustc-cdylib-link-arg={}", line);
    }

    #[cfg(unix)]
    {
        // Create a symlink.
        let mut create = true;

        let mut link = build_dir.clone();
        link.push(format!("librpm_sequoia.so.{}", major));

        if let Ok(current) = std::fs::read_link(&link) {
            if current.to_str() == Some("librpm_sequoia.so") {
                // Do nothing.
                create = false;
            } else {
                // Invalid.
                std::fs::remove_file(&link)?;
            }
        }

        if create {
            std::os::unix::fs::symlink("librpm_sequoia.so", link)?;
        }
    }

    Ok(())
}
