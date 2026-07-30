use crate::env_cfg;
use anyhow::{bail, Result};
use std::fs;

pub fn remove(target: &str, fool_flag: bool) -> Result<()> {
    env_cfg::ensure_dirs()?;
    if target == "fool" {
        let dir = env_cfg::cabt_home().join("fool");
        if dir.is_dir() {
            for e in fs::read_dir(&dir)? {
                let e = e?;
                let _ = fs::remove_file(e.path());
            }
        }
        println!("\x1b[31m fool results cleared\x1b[0m");
        return Ok(());
    }
    let dir = if fool_flag {
        env_cfg::cabt_home().join("fool")
    } else {
        env_cfg::cabt_home().join("result")
    };
    if !dir.is_dir() {
        bail!("no result dir");
    }
    let mut removed = false;
    for e in fs::read_dir(&dir)? {
        let e = e?;
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with(target) {
            fs::remove_file(e.path())?;
            removed = true;
        }
    }
    let _ = fs::remove_file(dir.join(".collect"));
    let _ = fs::remove_file(dir.join("one-worker.csv"));
    let _ = fs::remove_file(dir.join("more-worker.csv"));
    if removed {
        println!("\x1b[31m task wid: {target} removed!\x1b[0m");
    } else {
        println!("\x1b[31m no exist wid: {target} \x1b[0m");
    }
    Ok(())
}
