//! Hand-written store-only ZIP writer over a spool file.
//!
//! Entries are written with placeholder CRC/sizes in the local header, bytes
//! are streamed through a CRC32, then the header is patched via seek. The
//! central directory carries the final values, so any standard unzip reads it.

use tokio::fs::File;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

fn crc32_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 { 0xEDB88320 ^ (c >> 1) } else { c >> 1 };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
}

pub struct Crc32 {
    table: [u32; 256],
    state: u32,
}

impl Crc32 {
    pub fn new() -> Self {
        Crc32 {
            table: crc32_table(),
            state: 0xFFFF_FFFF,
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.state = self.table[((self.state ^ b as u32) & 0xFF) as usize] ^ (self.state >> 8);
        }
    }
    pub fn finish(&self) -> u32 {
        self.state ^ 0xFFFF_FFFF
    }
}

struct Entry {
    name: Vec<u8>,
    offset: u64,
    crc: u32,
    size: u64,
}

pub struct ZipWriter {
    file: File,
    pos: u64,
    entries: Vec<Entry>,
}

const DOS_DATE: u16 = ((2026 - 1980) << 9) | (1 << 5) | 1; // 2026-01-01
const DOS_TIME: u16 = 0;

impl ZipWriter {
    pub fn new(file: File) -> Self {
        ZipWriter {
            file,
            pos: 0,
            entries: Vec::new(),
        }
    }

    async fn put(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.file.write_all(data).await?;
        self.pos += data.len() as u64;
        Ok(())
    }

    /// Begin an entry; returns after writing the (placeholder) local header.
    pub async fn begin_entry(&mut self, name: &str) -> std::io::Result<()> {
        let name_b = name.as_bytes().to_vec();
        let offset = self.pos;
        let mut h = Vec::with_capacity(30 + name_b.len());
        h.extend_from_slice(&0x04034b50u32.to_le_bytes()); // local header sig
        h.extend_from_slice(&20u16.to_le_bytes()); // version needed
        h.extend_from_slice(&0x0800u16.to_le_bytes()); // flags: UTF-8 names
        h.extend_from_slice(&0u16.to_le_bytes()); // method: store
        h.extend_from_slice(&DOS_TIME.to_le_bytes());
        h.extend_from_slice(&DOS_DATE.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // crc placeholder
        h.extend_from_slice(&0u32.to_le_bytes()); // comp size placeholder
        h.extend_from_slice(&0u32.to_le_bytes()); // uncomp size placeholder
        h.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes()); // extra len
        h.extend_from_slice(&name_b);
        self.put(&h).await?;
        self.entries.push(Entry {
            name: name_b,
            offset,
            crc: 0,
            size: 0,
        });
        Ok(())
    }

    pub async fn entry_data(&mut self, data: &[u8], crc: &mut Crc32) -> std::io::Result<()> {
        crc.update(data);
        self.put(data).await
    }

    /// Finish the entry: patch CRC and sizes into its local header.
    pub async fn end_entry(&mut self, crc: Crc32, size: u64) -> std::io::Result<()> {
        if size > u32::MAX as u64 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "entry too large for zip32",
            ));
        }
        let e = self.entries.last_mut().expect("entry open");
        e.crc = crc.finish();
        e.size = size;
        let patch_at = e.offset + 14;
        let mut patch = Vec::with_capacity(12);
        patch.extend_from_slice(&e.crc.to_le_bytes());
        patch.extend_from_slice(&(size as u32).to_le_bytes());
        patch.extend_from_slice(&(size as u32).to_le_bytes());
        self.file
            .seek(std::io::SeekFrom::Start(patch_at))
            .await?;
        self.file.write_all(&patch).await?;
        self.file.seek(std::io::SeekFrom::Start(self.pos)).await?;
        Ok(())
    }

    /// Write central directory + end record and flush. Returns total size.
    pub async fn finish(mut self) -> std::io::Result<(File, u64)> {
        let cd_start = self.pos;
        let mut count = 0u16;
        let entries = std::mem::take(&mut self.entries);
        for e in &entries {
            let mut h = Vec::with_capacity(46 + e.name.len());
            h.extend_from_slice(&0x02014b50u32.to_le_bytes()); // central dir sig
            h.extend_from_slice(&20u16.to_le_bytes()); // version made by
            h.extend_from_slice(&20u16.to_le_bytes()); // version needed
            h.extend_from_slice(&0x0800u16.to_le_bytes()); // flags: UTF-8
            h.extend_from_slice(&0u16.to_le_bytes()); // store
            h.extend_from_slice(&DOS_TIME.to_le_bytes());
            h.extend_from_slice(&DOS_DATE.to_le_bytes());
            h.extend_from_slice(&e.crc.to_le_bytes());
            h.extend_from_slice(&(e.size as u32).to_le_bytes());
            h.extend_from_slice(&(e.size as u32).to_le_bytes());
            h.extend_from_slice(&(e.name.len() as u16).to_le_bytes());
            h.extend_from_slice(&0u16.to_le_bytes()); // extra
            h.extend_from_slice(&0u16.to_le_bytes()); // comment
            h.extend_from_slice(&0u16.to_le_bytes()); // disk
            h.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            h.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            h.extend_from_slice(&(e.offset as u32).to_le_bytes());
            h.extend_from_slice(&e.name);
            self.put(&h).await?;
            count += 1;
        }
        let cd_size = self.pos - cd_start;
        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(&0x06054b50u32.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // disk
        eocd.extend_from_slice(&0u16.to_le_bytes()); // cd disk
        eocd.extend_from_slice(&count.to_le_bytes());
        eocd.extend_from_slice(&count.to_le_bytes());
        eocd.extend_from_slice(&(cd_size as u32).to_le_bytes());
        eocd.extend_from_slice(&(cd_start as u32).to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // comment len
        self.put(&eocd).await?;
        self.file.flush().await?;
        let total = self.pos;
        Ok((self.file, total))
    }
}
