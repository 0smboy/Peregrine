use crate::env_cfg;
use anyhow::{bail, Result};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

pub fn list_results(mode: Option<&str>) -> Result<()> {
    let fool = matches!(mode, Some(m) if m == "fool");
    let result_dir = if fool {
        env_cfg::cabt_home().join("fool")
    } else {
        env_cfg::cabt_home().join("result")
    };
    if fool && !result_dir.is_dir() {
        bail!("no fool result! Try `cabt run fool` first.");
    }
    env_cfg::ensure_dirs()?;
    fs::create_dir_all(&result_dir)?;

    println!("--------------------------------------------------------------------------------------------------------------------------------------------------");
    println!("| W-id | Obj-Size | Op-Type | Worker | Op-Count |  Byte-Count  | Avg-ResTime | Avg-ProcTime |  Throughput  |  Bandwidth  |          Time         |");
    println!("--------------------------------------------------------------------------------------------------------------------------------------------------");

    let collect_file = result_dir.join(".collect");
    if collect_file.is_file() {
        for line in BufReader::new(fs::File::open(&collect_file)?).lines() {
            let line = line?;
            let c: Vec<_> = line.split(',').collect();
            if c.len() < 13 {
                continue;
            }
            printf_row(c[6], c[1], c[3], c[2], c[4], c[5], c[9], c[10], c[11], c[12], c[0]);
        }
    } else {
        let mut files: Vec<_> = fs::read_dir(&result_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.extension().and_then(|s| s.to_str()) == Some("csv")
                    && p.file_name()
                        .and_then(|s| s.to_str())
                        .map(|s| s.contains('B') || s.starts_with('w'))
                        .unwrap_or(false)
            })
            .collect();
        files.sort();
        let mut out = fs::File::create(&collect_file)?;
        for file in files {
            if let Some(row) = summarize_csv(&file)? {
                printf_row(
                    &row.wid,
                    &row.obj_size,
                    &row.op_type,
                    &row.worker,
                    &row.op_count,
                    &row.byte_count,
                    &row.avg_res,
                    &row.avg_proc,
                    &row.throughput,
                    &row.bandwidth,
                    &row.time,
                );
                writeln!(
                    out,
                    "{},{},{},{},{},{},{},,10,{},{},{},{}",
                    row.time,
                    row.obj_size,
                    row.worker,
                    row.op_type,
                    row.op_count,
                    row.byte_count,
                    row.wid,
                    row.avg_res,
                    row.avg_proc,
                    row.throughput,
                    row.bandwidth
                )?;
                if fool {
                    let dest = if row.worker == "1" {
                        result_dir.join("one-worker.csv")
                    } else {
                        result_dir.join("more-worker.csv")
                    };
                    let mut f = fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(dest)?;
                    writeln!(
                        f,
                        "{},,10,{},{},{},{}",
                        row.wid, row.avg_res, row.avg_proc, row.throughput, row.bandwidth
                    )?;
                }
            }
        }
    }
    println!("--------------------------------------------------------------------------------------------------------------------------------------------------");
    Ok(())
}

struct Row {
    wid: String,
    obj_size: String,
    op_type: String,
    worker: String,
    op_count: String,
    byte_count: String,
    avg_res: String,
    avg_proc: String,
    throughput: String,
    bandwidth: String,
    time: String,
}

fn summarize_csv(path: &Path) -> Result<Option<Row>> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_string();
    // expected: w1-64KB-write-100-2026-....csv
    let stem = name.trim_end_matches(".csv");
    let parts: Vec<_> = stem.split('-').collect();
    if parts.len() < 4 {
        return Ok(None);
    }
    let wid = parts[0].to_string();
    let obj_size = parts[1].to_string();
    let op_type = parts[2].to_string();
    let worker = parts[3].to_string();
    let time = if stem.len() >= 19 {
        stem[stem.len() - 19..].to_string()
    } else {
        String::new()
    };

    let mut rdr = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(path)?;
    let mut op_count = 0.0f64;
    let mut byte_count = 0.0f64;
    let mut res = 0.0f64;
    let mut proc = 0.0f64;
    let mut thr = 0.0f64;
    let mut bw = 0.0f64;
    let mut n = 0.0f64;
    for rec in rdr.records() {
        let rec = rec?;
        if rec.len() < 8 {
            continue;
        }
        // skip header-ish
        if rec[2].chars().any(|c| c.is_ascii_alphabetic()) && n == 0.0 {
            // might be header if Op-Count is text
            if rec[2].contains("Count") {
                continue;
            }
        }
        op_count += rec[2].parse().unwrap_or(0.0);
        byte_count += rec[3].parse().unwrap_or(0.0);
        res += rec[4].parse().unwrap_or(0.0);
        proc += rec[5].parse().unwrap_or(0.0);
        thr += rec[6].parse().unwrap_or(0.0);
        bw += rec[7].parse().unwrap_or(0.0);
        n += 1.0;
    }
    if n < 1.0 {
        return Ok(None);
    }
    let byte_s = if byte_count / 1e9 > 1.0 {
        format!("{:.2} GB", byte_count / 1e9)
    } else {
        format!("{:.2} MB", byte_count / 1e6)
    };
    // bw is bytes/s (COSBench Bandwidth column)
    let bw_s = if bw >= 1e6 {
        format!("{:.2} MB/s", bw / 1e6)
    } else if bw >= 1e3 {
        format!("{:.2} KB/s", bw / 1e3)
    } else {
        format!("{:.2} B/s", bw)
    };
    Ok(Some(Row {
        wid,
        obj_size,
        op_type,
        worker,
        op_count: format!("{op_count:.0}"),
        byte_count: byte_s,
        avg_res: format!("{:.2} ms", res / n),
        avg_proc: format!("{:.2} ms", proc / n),
        throughput: format!("{:.2} op/s", thr),
        bandwidth: bw_s,
        time,
    }))
}

fn printf_row(
    wid: &str,
    obj: &str,
    op: &str,
    worker: &str,
    opc: &str,
    bytes: &str,
    res: &str,
    proc: &str,
    thr: &str,
    bw: &str,
    time: &str,
) {
    println!(
        "| {wid:<4} | {obj:<8} |  {op:<6} | {worker:<6} | {opc:<8} | {bytes:<12} | {res:<11} | {proc:<12} | {thr:<12} | {bw:<11} |  {time:<12}  |"
    );
}
