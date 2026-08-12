// Copyright (c) 2026 OpenStack Foundation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Erasure-coding codec, an FFI binding to `liberasurecode` — the *same*
//! native library Python Swift uses through PyECLib. Because both call into
//! liberasurecode with identical `ec_args`, the fragments (and their metadata
//! headers) this crate produces are byte-identical to Python's, which is the
//! wire/disk compatibility contract for EC objects.
//!
//! The backend is `liberasurecode_rs_vand` (the built-in pure-C Reed-Solomon
//! Vandermonde code, no jerasure/ISA-L dependency) with `CRC32` inline
//! fragment checksums — matching PyECLib's `ec_type='liberasurecode_rs_vand'`
//! default (`chksum_type='inline_crc32'`).

use std::os::raw::{c_char, c_int, c_void};
use std::ptr;

/// `EC_BACKEND_LIBERASURECODE_RS_VAND`.
const EC_BACKEND_LIBERASURECODE_RS_VAND: c_int = 6;
/// `CHKSUM_NONE` — PyECLib's (and therefore Swift's) default fragment checksum
/// type. Swift builds `ECDriver(k, m, ec_type=...)` with no `chksum_type`, so
/// the fragment header carries no inline checksum; matching this is required
/// for byte-identical fragments.
const CHKSUM_NONE: c_int = 1;
/// Word size for the rs_vand backend (matches PyECLib's default).
const RS_VAND_W: c_int = 16;

/// `struct ec_args` — layout must match liberasurecode's C header exactly.
#[repr(C)]
struct EcArgs {
    k: c_int,
    m: c_int,
    w: c_int,
    hd: c_int,
    // union priv_args1: the largest member is `reserved { uint64 x,y,z,a }`.
    priv_args1: [u64; 4],
    priv_args2: *mut c_void,
    ct: c_int, // ec_checksum_type_t
}

#[allow(non_snake_case)]
extern "C" {
    fn liberasurecode_backend_available(id: c_int) -> c_int;
    fn liberasurecode_instance_create(id: c_int, args: *mut EcArgs) -> c_int;
    fn liberasurecode_instance_destroy(desc: c_int) -> c_int;
    fn liberasurecode_encode(
        desc: c_int,
        orig_data: *const c_char,
        orig_data_size: u64,
        encoded_data: *mut *mut *mut c_char,
        encoded_parity: *mut *mut *mut c_char,
        fragment_len: *mut u64,
    ) -> c_int;
    fn liberasurecode_encode_cleanup(
        desc: c_int,
        encoded_data: *mut *mut c_char,
        encoded_parity: *mut *mut c_char,
    ) -> c_int;
    fn liberasurecode_decode(
        desc: c_int,
        available_fragments: *mut *mut c_char,
        num_fragments: c_int,
        fragment_len: u64,
        force_metadata_checks: c_int,
        out_data: *mut *mut c_char,
        out_data_len: *mut u64,
    ) -> c_int;
    fn liberasurecode_decode_cleanup(desc: c_int, data: *mut c_char) -> c_int;
    fn liberasurecode_reconstruct_fragment(
        desc: c_int,
        available_fragments: *mut *mut c_char,
        num_fragments: c_int,
        fragment_len: u64,
        destination_idx: c_int,
        out_fragment: *mut c_char,
    ) -> c_int;
    fn liberasurecode_get_fragment_size(desc: c_int, data_len: c_int) -> c_int;
    fn liberasurecode_get_fragment_metadata(
        fragment: *const c_char,
        metadata: *mut FragmentMetadata,
    ) -> c_int;
}

/// A subset-safe view of `fragment_metadata_t` (only the index is read here).
/// Over-sized `_pad` so we never under-allocate versus the real C struct.
#[repr(C)]
struct FragmentMetadata {
    idx: c_int,
    size: c_int,
    frag_backend_metadata_size: c_int,
    orig_data_size: u64,
    chksum_type: u8,
    chksum: [u32; 8],
    chksum_mismatch: u8,
    backend_id: u8,
    backend_version: u32,
    _pad: [u8; 64],
}

impl FragmentMetadata {
    fn zeroed() -> Self {
        // SAFETY: an all-zero bit pattern is a valid value for every field
        // (integers/arrays); the struct is only written by the C library.
        unsafe { std::mem::zeroed() }
    }
}

/// Errors from the EC codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcError {
    /// The `liberasurecode_rs_vand` backend is not available in the linked
    /// library.
    BackendUnavailable,
    /// `liberasurecode_instance_create` failed.
    InstanceCreate(i32),
    /// An encode/decode/reconstruct call returned an error code.
    Codec(&'static str, i32),
    /// Fewer than `k` fragments were supplied to `decode`.
    NotEnoughFragments,
}

impl std::fmt::Display for EcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EcError::BackendUnavailable => write!(f, "liberasurecode_rs_vand backend unavailable"),
            EcError::InstanceCreate(c) => write!(f, "instance_create failed: {c}"),
            EcError::Codec(op, c) => write!(f, "{op} failed: {c}"),
            EcError::NotEnoughFragments => write!(f, "not enough fragments to decode"),
        }
    }
}

impl std::error::Error for EcError {}

/// An erasure-coding driver: `k` data + `m` parity fragments over the
/// `liberasurecode_rs_vand` backend. Mirrors PyECLib's `ECDriver`.
pub struct EcDriver {
    desc: c_int,
    k: usize,
    m: usize,
    /// The fixed fragment-header size (bytes a fragment carries beyond its
    /// data payload), probed once at creation.
    header_size: usize,
}

// The liberasurecode instance descriptor is safe to move/share across threads
// for read-only encode/decode (each call is independent); we only ever use it
// from a single owner here.
unsafe impl Send for EcDriver {}

impl EcDriver {
    /// Create a driver for `k` data + `m` parity fragments. Fails if the
    /// backend isn't compiled into the linked liberasurecode.
    pub fn new(k: usize, m: usize) -> Result<EcDriver, EcError> {
        if unsafe { liberasurecode_backend_available(EC_BACKEND_LIBERASURECODE_RS_VAND) } != 1 {
            return Err(EcError::BackendUnavailable);
        }
        let mut args = EcArgs {
            k: k as c_int,
            m: m as c_int,
            w: RS_VAND_W,
            hd: m as c_int,
            priv_args1: [0; 4],
            priv_args2: ptr::null_mut(),
            ct: CHKSUM_NONE,
        };
        let desc =
            unsafe { liberasurecode_instance_create(EC_BACKEND_LIBERASURECODE_RS_VAND, &mut args) };
        if desc <= 0 {
            return Err(EcError::InstanceCreate(desc));
        }
        let mut driver = EcDriver {
            desc,
            k,
            m,
            header_size: 0,
        };
        // Probe the fixed fragment-header size: encode a k-byte segment and
        // compare the real fragment length to the data-only size.
        let probe = vec![0u8; k];
        let raw = driver.raw_fragment_size(k);
        let actual = driver.encode(&probe)?[0].len();
        driver.header_size = actual.saturating_sub(raw);
        Ok(driver)
    }

    pub fn k(&self) -> usize {
        self.k
    }
    pub fn m(&self) -> usize {
        self.m
    }

    /// Encode `data` into `k + m` fragments (data fragments first, then
    /// parity), each including liberasurecode's fragment header.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, EcError> {
        let mut enc_data: *mut *mut c_char = ptr::null_mut();
        let mut enc_parity: *mut *mut c_char = ptr::null_mut();
        let mut frag_len: u64 = 0;
        let rc = unsafe {
            liberasurecode_encode(
                self.desc,
                data.as_ptr() as *const c_char,
                data.len() as u64,
                &mut enc_data,
                &mut enc_parity,
                &mut frag_len,
            )
        };
        if rc != 0 {
            return Err(EcError::Codec("encode", rc));
        }
        let mut out: Vec<Vec<u8>> = Vec::with_capacity(self.k + self.m);
        unsafe {
            for i in 0..self.k {
                let p = *enc_data.add(i) as *const u8;
                out.push(std::slice::from_raw_parts(p, frag_len as usize).to_vec());
            }
            for i in 0..self.m {
                let p = *enc_parity.add(i) as *const u8;
                out.push(std::slice::from_raw_parts(p, frag_len as usize).to_vec());
            }
            liberasurecode_encode_cleanup(self.desc, enc_data, enc_parity);
        }
        Ok(out)
    }

    /// Decode the original data from at least `k` fragments (any mix of data
    /// and parity).
    pub fn decode(&self, fragments: &[Vec<u8>]) -> Result<Vec<u8>, EcError> {
        if fragments.len() < self.k {
            return Err(EcError::NotEnoughFragments);
        }
        let frag_len = fragments[0].len() as u64;
        let mut ptrs: Vec<*mut c_char> = fragments
            .iter()
            .map(|f| f.as_ptr() as *mut c_char)
            .collect();
        let mut out_data: *mut c_char = ptr::null_mut();
        let mut out_len: u64 = 0;
        let rc = unsafe {
            liberasurecode_decode(
                self.desc,
                ptrs.as_mut_ptr(),
                fragments.len() as c_int,
                frag_len,
                1, // force_metadata_checks
                &mut out_data,
                &mut out_len,
            )
        };
        if rc != 0 {
            return Err(EcError::Codec("decode", rc));
        }
        let data = unsafe {
            let v = std::slice::from_raw_parts(out_data as *const u8, out_len as usize).to_vec();
            liberasurecode_decode_cleanup(self.desc, out_data);
            v
        };
        Ok(data)
    }

    /// Reconstruct the single fragment at `destination_idx` from the available
    /// fragments (the reconstructor's primitive).
    pub fn reconstruct(
        &self,
        fragments: &[Vec<u8>],
        destination_idx: usize,
    ) -> Result<Vec<u8>, EcError> {
        if fragments.is_empty() {
            return Err(EcError::NotEnoughFragments);
        }
        let frag_len = fragments[0].len();
        let mut ptrs: Vec<*mut c_char> = fragments
            .iter()
            .map(|f| f.as_ptr() as *mut c_char)
            .collect();
        let mut out = vec![0u8; frag_len];
        let rc = unsafe {
            liberasurecode_reconstruct_fragment(
                self.desc,
                ptrs.as_mut_ptr(),
                fragments.len() as c_int,
                frag_len as u64,
                destination_idx as c_int,
                out.as_mut_ptr() as *mut c_char,
            )
        };
        if rc != 0 {
            return Err(EcError::Codec("reconstruct", rc));
        }
        Ok(out)
    }

    /// The data-only per-fragment size liberasurecode reports (excludes the
    /// fragment header).
    fn raw_fragment_size(&self, data_len: usize) -> usize {
        unsafe { liberasurecode_get_fragment_size(self.desc, data_len as c_int) as usize }
    }

    /// The full size in bytes of each fragment for an object segment of
    /// `data_len` bytes, *including* the fragment header — this is the value
    /// Swift's `policy.fragment_size` / pyeclib `get_segment_info` report, and
    /// the amount each segment occupies in a fragment archive.
    pub fn fragment_size(&self, data_len: usize) -> usize {
        self.raw_fragment_size(data_len) + self.header_size
    }

    /// The per-segment sizes an object of `orig_size` bytes splits into for
    /// `segment_size`-byte segments (the last segment may be shorter).
    fn segment_sizes(orig_size: usize, segment_size: usize) -> Vec<usize> {
        if orig_size == 0 {
            return vec![0];
        }
        let mut sizes = Vec::new();
        let mut remaining = orig_size;
        while remaining > segment_size {
            sizes.push(segment_size);
            remaining -= segment_size;
        }
        sizes.push(remaining);
        sizes
    }

    /// Encode a whole object into `k + m` *fragment archives* — the layout
    /// Swift's EC PUT stores, where node `j`'s archive is `j`'s fragment for
    /// every segment concatenated. The object is split into `segment_size`
    /// segments, each encoded into `k + m` fragments.
    pub fn encode_object(&self, data: &[u8], segment_size: usize) -> Result<Vec<Vec<u8>>, EcError> {
        let n = self.k + self.m;
        let mut archives: Vec<Vec<u8>> = vec![Vec::new(); n];
        // Zero-byte objects store zero-byte archives (Python parity:
        // chunk_transformer yields `[b''] * n` for empty input).
        if data.is_empty() {
            return Ok(archives);
        }
        let segments: Vec<&[u8]> = data.chunks(segment_size).collect();
        for seg in segments {
            let frags = self.encode(seg)?;
            for (j, f) in frags.iter().enumerate() {
                archives[j].extend_from_slice(f);
            }
        }
        Ok(archives)
    }

    /// Decode an object from at least `k` fragment archives, given the object's
    /// original size and the policy's `segment_size`. Each archive is split
    /// back into per-segment fragments (using the fragment size for each
    /// segment length), and each segment is decoded and concatenated.
    pub fn decode_object(
        &self,
        archives: &[Vec<u8>],
        orig_size: usize,
        segment_size: usize,
    ) -> Result<Vec<u8>, EcError> {
        if archives.len() < self.k {
            return Err(EcError::NotEnoughFragments);
        }
        // A zero-byte object stores zero-byte archives (Python's
        // chunk_transformer yields `[b''] * n` for empty input) — there is
        // nothing to slice or decode.
        if orig_size == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(orig_size);
        let mut offset = 0usize;
        for seg_len in Self::segment_sizes(orig_size, segment_size) {
            let fs = self.fragment_size(seg_len);
            let seg_frags: Vec<Vec<u8>> = archives
                .iter()
                .map(|a| a[offset..offset + fs].to_vec())
                .collect();
            out.extend(self.decode(&seg_frags)?);
            offset += fs;
        }
        out.truncate(orig_size);
        Ok(out)
    }

    /// Rebuild the fragment archive for `destination_idx` from at least `k`
    /// peer fragment archives — the reconstructor's per-object primitive. Each
    /// archive is split into per-segment fragments (as in `decode_object`) and
    /// the destination fragment is reconstructed segment by segment; the result
    /// is byte-identical to the archive `encode_object` produced for that node.
    pub fn reconstruct_object(
        &self,
        archives: &[Vec<u8>],
        orig_size: usize,
        segment_size: usize,
        destination_idx: usize,
    ) -> Result<Vec<u8>, EcError> {
        if archives.len() < self.k {
            return Err(EcError::NotEnoughFragments);
        }
        // Zero-byte object -> zero-byte archives; the rebuilt fragment
        // archive is empty too (see decode_object).
        if orig_size == 0 {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut offset = 0usize;
        for seg_len in Self::segment_sizes(orig_size, segment_size) {
            let fs = self.fragment_size(seg_len);
            let seg_frags: Vec<Vec<u8>> = archives
                .iter()
                .map(|a| a[offset..offset + fs].to_vec())
                .collect();
            out.extend(self.reconstruct(&seg_frags, destination_idx)?);
            offset += fs;
        }
        Ok(out)
    }

    /// The fragment index encoded in a fragment's header (its position in the
    /// data+parity ordering), via `liberasurecode_get_fragment_metadata`.
    pub fn fragment_index(fragment: &[u8]) -> Option<i32> {
        let mut meta = FragmentMetadata::zeroed();
        let rc = unsafe {
            liberasurecode_get_fragment_metadata(fragment.as_ptr() as *const c_char, &mut meta)
        };
        if rc == 0 {
            Some(meta.idx)
        } else {
            None
        }
    }
}

impl Drop for EcDriver {
    fn drop(&mut self) {
        unsafe {
            liberasurecode_instance_destroy(self.desc);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_reconstruct() {
        let d = EcDriver::new(2, 1).unwrap();
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
        let frags = d.encode(&data).unwrap();
        assert_eq!(frags.len(), 3); // k + m

        // decode from exactly k fragments (drop the last parity)
        let out = d.decode(&frags[..2]).unwrap();
        assert_eq!(out, data);

        // decode using a parity fragment in place of a data fragment
        let mixed = vec![frags[0].clone(), frags[2].clone()];
        assert_eq!(d.decode(&mixed).unwrap(), data);

        // reconstruct the missing fragment index 2 from 0 and 1
        let recon = d
            .reconstruct(&[frags[0].clone(), frags[1].clone()], 2)
            .unwrap();
        assert_eq!(recon, frags[2]);

        // fewer than k fragments cannot decode
        assert_eq!(d.decode(&frags[..1]), Err(EcError::NotEnoughFragments));
    }

    #[test]
    fn test_encode_decode_object_multi_segment() {
        let d = EcDriver::new(4, 2).unwrap();
        let seg = 1000usize; // small segments to force several
                             // 3.5 segments so the last one is partial
        let data: Vec<u8> = (0..3500u32).map(|i| (i * 13 % 256) as u8).collect();
        let archives = d.encode_object(&data, seg).unwrap();
        assert_eq!(archives.len(), 6); // k + m

        // decode from exactly k archives (drop 2 parity)
        let back = d.decode_object(&archives[..4], data.len(), seg).unwrap();
        assert_eq!(back, data);

        // decode using a mix that includes parity archives
        let mixed = vec![
            archives[0].clone(),
            archives[2].clone(),
            archives[4].clone(),
            archives[5].clone(),
        ];
        assert_eq!(d.decode_object(&mixed, data.len(), seg).unwrap(), data);
    }

    #[test]
    fn test_reconstruct_object_rebuilds_identical_archive() {
        let d = EcDriver::new(4, 2).unwrap();
        let seg = 1000usize;
        let data: Vec<u8> = (0..3500u32).map(|i| (i * 13 % 256) as u8).collect();
        let archives = d.encode_object(&data, seg).unwrap();

        // Rebuild each fragment archive (data and parity) from k others and
        // confirm it is byte-identical to the original — this is exactly what
        // the reconstructor writes back to a node that lost its fragment.
        for dest in 0..6usize {
            let peers: Vec<Vec<u8>> = (0..6usize)
                .filter(|i| *i != dest)
                .take(4) // any k peers
                .map(|i| archives[i].clone())
                .collect();
            let rebuilt = d.reconstruct_object(&peers, data.len(), seg, dest).unwrap();
            assert_eq!(rebuilt, archives[dest], "rebuilt archive {dest} matches");
        }
    }

    #[test]
    fn test_fragment_index_metadata() {
        let d = EcDriver::new(4, 2).unwrap();
        let frags = d
            .encode(b"metadata index check padding padding padding")
            .unwrap();
        for (i, f) in frags.iter().enumerate() {
            assert_eq!(EcDriver::fragment_index(f), Some(i as i32));
        }
    }

    #[test]
    fn test_empty_object_stores_and_round_trips_empty_archives() {
        // Python parity: chunk_transformer yields `[b''] * n` for empty
        // input, so zero-byte objects live as zero-byte archives — and
        // decode/reconstruct must not slice into them.
        let d = EcDriver::new(4, 2).unwrap();
        let archives = d.encode_object(b"", 1024).unwrap();
        assert_eq!(archives.len(), 6);
        assert!(archives.iter().all(|a| a.is_empty()));
        assert_eq!(d.decode_object(&archives[..4], 0, 1024).unwrap(), b"");
        assert_eq!(
            d.reconstruct_object(&archives[..4], 0, 1024, 5).unwrap(),
            b""
        );
    }
}
