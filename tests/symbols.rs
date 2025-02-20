use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use assert_cmd::Command;
use assert_cmd::assert::OutputAssertExt;

#[test]
fn symbols() -> anyhow::Result<()> {
    // Make sure the library is built.
    Command::new("cargo").arg("build").ok()?;

    // We want the location of the build directory (e.g.,
    // `/tmp/rpm-sequoia/debug`).
    //
    // OUT_DIR gives us
    // `/tmp/rpm-sequoia/debug/build/rpm-sequoia-HASH/out`.

    let out_dir = PathBuf::from(env!("OUT_DIR"));
    let mut build_dir = out_dir;
    let lib = loop {
        let mut lib = build_dir.clone();
        lib.push("librpm_sequoia.so");
        if lib.exists() {
            break lib;
        }
        if ! build_dir.pop() {
            panic!("Failed to find librpm_sequoia.so");
        }
    };

    let cmd = Command::new("objdump")
        .arg("-T")
        .arg(lib)
        .unwrap();

    let assert = cmd.assert().success();
    let output = String::from_utf8_lossy(&assert.get_output().stdout);

    let mut symbols = Vec::new();
    for line in output.split("\n") {
        if line.contains("g    DF .text")
            || line.contains("g    DO .data")
            || line.contains("g    DF .opd")
        {
            let symbol = line.split(' ').last().expect("a word");
            symbols.push(symbol);
        }
    }
    symbols.sort();

    eprintln!("Found {} symbols:", symbols.len());
    for symbol in symbols.iter() {
        eprintln!("  {}", symbol);
    }

    let mut expected_symbols_txt_fn
        = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    expected_symbols_txt_fn.push("src/symbols.txt");

    let mut expected_symbols_txt = Vec::new();
    File::open(expected_symbols_txt_fn)
        .expect("src/symbols.txt exists")
        .read_to_end(&mut expected_symbols_txt)
        .unwrap();
    let expected_symbols_txt
        = String::from_utf8_lossy(&expected_symbols_txt);

    let mut expected_symbols = Vec::new();
    for symbol in expected_symbols_txt.split("\n") {
        if symbol.starts_with("#") {
            continue;
        }
        let symbol = symbol.trim();
        if symbol.is_empty() {
            continue;
        }
        if symbol.chars().nth(0) == Some('?') {
            expected_symbols.push((&symbol[1..], true));
        } else {
            expected_symbols.push((symbol, false));
        }
    }
    expected_symbols.sort();

    eprintln!("Expected {} symbols:", expected_symbols.len());
    for (symbol, optional) in expected_symbols.iter() {
        eprint!("  {}", symbol);
        if *optional {
            eprintln!(" (optional)");
        } else {
            eprintln!("");
        }
    }

    let mut i = 0;
    let mut j = 0;
    let mut bad = false;
    loop {
        if i == symbols.len() && j == expected_symbols.len() {
            break;
        }

        if i < symbols.len()
            && j < expected_symbols.len()
            && symbols[i] == expected_symbols[j].0
        {
            i += 1;
            j += 1;
        } else if (i < symbols.len()
                   && j < expected_symbols.len()
                   && symbols[i] < expected_symbols[j].0)
            || j == expected_symbols.len()
        {
            eprintln!("Found unexpected symbol {}", symbols[i]);
            if symbols[i] == "bz_internal_error" {
                eprintln!("  It looks like you forgot to disable compression.")
            }
            i += 1;
            bad = true;
        } else if (i < symbols.len()
                   && j < expected_symbols.len()
                   && symbols[i] > expected_symbols[j].0)
            || i == symbols.len()
        {
            if ! expected_symbols[j].1 {
                eprintln!("Missing expected symbol {}", expected_symbols[j].0);
                bad = true;
            }
            j += 1;
        } else {
            unreachable!();
        }
    }

    if bad {
        eprintln!("\
            *** If you see unexpected symbols like SHA1DCInit..., \
            then you need version 0.2.6 or later of \
            sha1collisiondetection. ***");
        Err(anyhow::anyhow!("symbol mismatch"))
    } else {
        Ok(())
    }
}
