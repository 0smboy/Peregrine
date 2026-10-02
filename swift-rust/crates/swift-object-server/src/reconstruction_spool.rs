//! Disk-backed EC reconstruction archives with a host-shared reservation
//! budget. Payload files are unlinked before their first write: dropping a
//! request, process exit, and SIGKILL cannot leave an archive pathname behind.
//! Small lease files are locked for their lifetime; the next reservation
//! reclaims leases from dead processes under the directory's budget lock.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use md5::{Digest, Md5};

const MAX_LEASES: usize = 4096;
const LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const LEASE_PREFIX: &str = ".lease-";
static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

fn retry(message: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        format!(
            "reconstruction spool resource unavailable (retryable): {}",
            message.into()
        ),
    )
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn open_at(directory: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn unlink_at(directory: &File, name: &CStr) -> io::Result<()> {
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
}

/// Walk from / using directory FDs, rejecting symlinks at every component.
/// Only the dedicated final directory must be private; ordinary parents such
/// as /var/tmp may be shared. No production device directory is used here.
fn private_directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(invalid(
            "reconstruction spool requires a dedicated absolute directory",
        ));
    }
    let mut directory = File::open("/")?;
    for component in path.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => {
                CString::new(name.as_bytes()).map_err(|_| invalid("NUL in spool path"))?
            }
            _ => return Err(invalid("spool path must not contain dot components")),
        };
        let next = match open_at(&directory, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let rc = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
                if rc != 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
                }
                open_at(&directory, &name, libc::O_RDONLY | libc::O_DIRECTORY, 0)?
            }
            Err(error) => return Err(error),
        };
        directory = next;
    }
    use std::os::unix::fs::MetadataExt;
    let metadata = directory.metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(invalid(
            "reconstruction spool directory must be owned by this uid and mode 0700",
        ));
    }
    let anchored = format!("/proc/self/fd/{}", directory.as_raw_fd());
    for (index, entry) in std::fs::read_dir(anchored)?.enumerate() {
        if index >= MAX_LEASES + 2 {
            return Err(retry("too many spool directory entries"));
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(invalid("invalid spool directory entry"));
        };
        if name != ".lock" && name != ".limit" && !name.starts_with(LEASE_PREFIX) {
            return Err(invalid(
                "reconstruction spool directory contains non-spool data",
            ));
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatfs(directory.as_raw_fd(), &mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if stat.f_type == libc::TMPFS_MAGIC || stat.f_type == 0x858458f6 {
            return Err(invalid(
                "reconstruction spool must use disk, not tmpfs/ramfs",
            ));
        }
    }
    Ok(directory)
}

fn lock_file(file: &File) -> io::Result<()> {
    let start = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) if start.elapsed() < LOCK_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(std::fs::TryLockError::WouldBlock) => return Err(retry("budget lock timeout")),
            Err(std::fs::TryLockError::Error(error)) => return Err(error),
        }
    }
}

struct BudgetInner {
    directory: File,
    max_bytes: u64,
    min_free_bytes: u64,
}

/// All daemon processes using the same directory share this byte budget.
/// Reservation denial is retryable; it must never authorize source deletion.
#[derive(Clone)]
pub struct SpoolBudget {
    inner: Arc<BudgetInner>,
}

impl std::fmt::Debug for SpoolBudget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SpoolBudget")
            .field("max_bytes", &self.inner.max_bytes)
            .finish()
    }
}

impl SpoolBudget {
    pub fn open(path: &Path, max_bytes: u64, min_free_bytes: u64) -> io::Result<Self> {
        if max_bytes == 0 {
            return Err(invalid("reconstruction spool budget must be positive"));
        }
        let budget = Self {
            inner: Arc::new(BudgetInner {
                directory: private_directory(path)?,
                max_bytes,
                min_free_bytes,
            }),
        };
        let _lock = budget.lock()?;
        // A shared directory must not silently acquire conflicting limits.
        let name = c".limit";
        let file = match open_at(
            &budget.inner.directory,
            name,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            0o600,
        ) {
            Ok(mut file) => {
                file.write_all(&max_bytes.to_le_bytes())?;
                file
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                open_at(&budget.inner.directory, name, libc::O_RDONLY, 0)?
            }
            Err(error) => return Err(error),
        };
        let mut raw = [0u8; 8];
        file.read_exact_at(&mut raw, 0)?;
        if file.metadata()?.len() != 8 || u64::from_le_bytes(raw) != max_bytes {
            return Err(invalid(
                "conflicting reconstruction spool budget for shared directory",
            ));
        }
        Ok(budget)
    }

    fn lock(&self) -> io::Result<File> {
        let file = open_at(
            &self.inner.directory,
            c".lock",
            libc::O_RDWR | libc::O_CREAT,
            0o600,
        )?;
        lock_file(&file)?;
        Ok(file)
    }

    fn reservations(&self) -> io::Result<(u64, usize)> {
        // /proc/self/fd resolves the already validated, held directory inode.
        // Every entry is opened relative to that inode with O_NOFOLLOW.
        let path = format!("/proc/self/fd/{}", self.inner.directory.as_raw_fd());
        let mut total = 0u64;
        let mut active = 0usize;
        let mut examined = 0usize;
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            examined += 1;
            if examined > MAX_LEASES + 2 {
                return Err(retry("too many spool directory entries"));
            }
            let raw_name = entry.file_name();
            let Some(name) = raw_name.to_str() else {
                return Err(invalid("non-UTF8 spool directory entry"));
            };
            if !name.starts_with(LEASE_PREFIX) {
                continue;
            }
            let name = CString::new(name).map_err(|_| invalid("invalid lease name"))?;
            let file = match open_at(&self.inner.directory, &name, libc::O_RDWR, 0) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            match file.try_lock() {
                // No process owns this lease. Payload was already anonymous
                // and died with its last FD; reclaim only the small lease.
                Ok(()) => {
                    unlink_at(&self.inner.directory, &name)?;
                    continue;
                }
                Err(std::fs::TryLockError::WouldBlock) => {}
                Err(std::fs::TryLockError::Error(error)) => return Err(error),
            }
            if !file.metadata()?.is_file() || file.metadata()?.len() != 8 {
                return Err(invalid("invalid live reconstruction spool lease"));
            }
            let mut raw = [0u8; 8];
            file.read_exact_at(&mut raw, 0)?;
            total = total
                .checked_add(u64::from_le_bytes(raw))
                .ok_or_else(|| retry("reservation sum overflow"))?;
            active += 1;
        }
        Ok((total, active))
    }

    pub fn reserved_bytes(&self) -> io::Result<u64> {
        let _lock = self.lock()?;
        Ok(self.reservations()?.0)
    }

    pub fn max_bytes(&self) -> u64 {
        self.inner.max_bytes
    }

    pub fn reserve(&self, expected_bytes: u64) -> io::Result<SpoolWriter> {
        let _lock = self.lock()?;
        let (used, active) = self.reservations()?;
        if active >= MAX_LEASES
            || used
                .checked_add(expected_bytes)
                .is_none_or(|total| total > self.inner.max_bytes)
        {
            return Err(retry(format!(
                "budget {} bytes, reserved {used}, requested {expected_bytes}",
                self.inner.max_bytes
            )));
        }
        let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatvfs(self.inner.directory.as_raw_fd(), &mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let available = (stat.f_bavail as u64)
            .checked_mul(stat.f_frsize as u64)
            .unwrap_or(0);
        if expected_bytes
            .checked_add(self.inner.min_free_bytes)
            .is_none_or(|required| required > available)
        {
            return Err(retry("insufficient disk space"));
        }
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let mut lease = None;
        for _ in 0..16 {
            let sequence = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
            let name = CString::new(format!(
                "{LEASE_PREFIX}{}-{stamp:x}-{sequence:x}",
                std::process::id()
            ))
            .unwrap();
            match open_at(
                &self.inner.directory,
                &name,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
                0o600,
            ) {
                Ok(file) => {
                    lease = Some(Lease {
                        file,
                        name,
                        budget: self.clone(),
                    });
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        let mut lease = lease.ok_or_else(|| retry("could not allocate unique lease"))?;
        lock_file(&lease.file)?;
        lease.file.write_all(&expected_bytes.to_le_bytes())?;
        let payload = anonymous_payload(&self.inner.directory)?;
        Ok(SpoolWriter {
            payload,
            lease,
            expected_bytes,
            written: 0,
            hasher: Md5::new(),
        })
    }
}

fn anonymous_payload(directory: &File) -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        return open_at(directory, c".", libc::O_RDWR | libc::O_TMPFILE, 0o600)
            .map_err(|error| retry(format!("anonymous disk files required: {error}")));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = directory;
        Err(retry("anonymous reconstruction spool requires Linux"))
    }
}

struct Lease {
    file: File,
    name: CString,
    budget: SpoolBudget,
}
impl Drop for Lease {
    fn drop(&mut self) {
        // The locked FD remains alive until after unlink, so another process
        // can never reap a lease that still owns a live archive.
        let _ = unlink_at(&self.budget.inner.directory, &self.name);
    }
}

struct DiskArchive {
    payload: File,
    _lease: Lease,
}
#[derive(Clone)]
enum Storage {
    Memory(Arc<[u8]>),
    Disk(Arc<DiskArchive>),
}

/// Rebuilt/source body without a full-object Vec requirement. Memory storage
/// is only the compatibility adapter used by small deterministic test fetchers.
#[derive(Clone)]
pub struct ArchiveBody {
    storage: Storage,
    len: u64,
    md5: String,
}
impl std::fmt::Debug for ArchiveBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArchiveBody")
            .field("len", &self.len)
            .field("disk_backed", &self.is_disk_backed())
            .finish()
    }
}
impl From<Vec<u8>> for ArchiveBody {
    fn from(bytes: Vec<u8>) -> Self {
        Self {
            len: bytes.len() as u64,
            md5: format!("{:x}", Md5::digest(&bytes)),
            storage: Storage::Memory(bytes.into()),
        }
    }
}
impl ArchiveBody {
    pub fn len(&self) -> u64 {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn is_disk_backed(&self) -> bool {
        matches!(&self.storage, Storage::Disk(_))
    }
    pub fn md5_hex(&self) -> &str {
        &self.md5
    }
    pub fn reader(&self) -> ArchiveReader {
        ArchiveReader {
            body: self.clone(),
            position: 0,
        }
    }
}

pub struct ArchiveReader {
    body: ArchiveBody,
    position: u64,
}
impl Read for ArchiveReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = output
            .len()
            .min(usize::try_from(self.body.len - self.position).unwrap_or(usize::MAX));
        if count == 0 {
            return Ok(0);
        }
        let read = match &self.body.storage {
            Storage::Memory(bytes) => {
                let start = usize::try_from(self.position)
                    .map_err(|_| invalid("archive cursor overflow"))?;
                output[..count].copy_from_slice(&bytes[start..start + count]);
                count
            }
            Storage::Disk(archive) => archive
                .payload
                .read_at(&mut output[..count], self.position)?,
        };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated reconstruction spool",
            ));
        }
        self.position += read as u64;
        Ok(read)
    }
}

pub struct SpoolWriter {
    payload: File,
    lease: Lease,
    expected_bytes: u64,
    written: u64,
    hasher: Md5,
}
impl Write for SpoolWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self
            .written
            .checked_add(bytes.len() as u64)
            .is_none_or(|next| next > self.expected_bytes)
        {
            return Err(invalid("reconstruction spool exceeded its reserved length"));
        }
        let written = self.payload.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        self.written += written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.payload.flush()
    }
}
impl SpoolWriter {
    pub fn finish(self) -> io::Result<ArchiveBody> {
        if self.written != self.expected_bytes {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete reconstruction spool",
            ));
        }
        Ok(self.finish_bounded())
    }

    /// For a framed stream without an advance exact length. The reservation
    /// remains at its original cap until this archive is dropped.
    pub(crate) fn finish_bounded(self) -> ArchiveBody {
        ArchiveBody {
            storage: Storage::Disk(Arc::new(DiskArchive {
                payload: self.payload,
                _lease: self.lease,
            })),
            len: self.written,
            md5: format!("{:x}", self.hasher.finalize()),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    struct TestRoot(std::path::PathBuf);
    impl TestRoot {
        fn new() -> Self {
            let path = std::path::PathBuf::from(format!(
                "/var/tmp/peregrine-spool-test-{}-{}",
                std::process::id(),
                NEXT_FILE.fetch_add(1, Ordering::Relaxed)
            ));
            Self(path)
        }
        fn budget(&self, bytes: u64) -> SpoolBudget {
            SpoolBudget::open(&self.0, bytes, 0).unwrap()
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn shared_budget_denies_then_retries_after_drop() {
        let root = TestRoot::new();
        let first = root.budget(10);
        let second = root.budget(10);
        let writer = first.reserve(7).unwrap();
        assert_eq!(
            second.reserve(4).err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(second.reserved_bytes().unwrap(), 7);
        drop(writer);
        assert_eq!(second.reserved_bytes().unwrap(), 0);
        assert!(second.reserve(10).is_ok());
    }

    #[test]
    fn anonymous_body_has_independent_readers_and_no_payload_path() {
        let root = TestRoot::new();
        let budget = root.budget(32);
        let mut writer = budget.reserve(8).unwrap();
        writer.write_all(b"abcdefgh").unwrap();
        let body = writer.finish().unwrap();
        assert!(body.is_disk_backed());
        use std::os::unix::fs::MetadataExt;
        let Storage::Disk(archive) = &body.storage else {
            panic!("expected disk body");
        };
        assert_eq!(archive.payload.metadata().unwrap().mode() & 0o777, 0o600);
        assert_eq!(archive.payload.metadata().unwrap().nlink(), 0);
        let mut a = body.reader();
        let mut b = body.reader();
        let mut left = [0u8; 4];
        let mut right = [0u8; 4];
        a.read_exact(&mut left).unwrap();
        b.read_exact(&mut right).unwrap();
        assert_eq!(&left, b"abcd");
        assert_eq!(&right, b"abcd");
        a.read_exact(&mut left).unwrap();
        assert_eq!(&left, b"efgh");
        drop(body);
        drop(a);
        drop(b);
        assert_eq!(budget.reserved_bytes().unwrap(), 0);
        assert!(std::fs::read_dir(&root.0).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".payload-")));
    }

    #[test]
    fn incomplete_or_oversized_archive_releases_reservation() {
        let root = TestRoot::new();
        let budget = root.budget(10);
        let mut writer = budget.reserve(4).unwrap();
        assert!(writer.write_all(b"12345").is_err());
        drop(writer);
        assert_eq!(budget.reserved_bytes().unwrap(), 0);
        let mut writer = budget.reserve(4).unwrap();
        writer.write_all(b"12").unwrap();
        assert!(writer.finish().is_err());
        assert_eq!(budget.reserved_bytes().unwrap(), 0);
    }

    #[test]
    fn stale_lease_is_reaped_and_symlink_path_is_rejected() {
        let root = TestRoot::new();
        let budget = root.budget(10);
        std::fs::write(root.0.join(".lease-dead-owner"), 10u64.to_le_bytes()).unwrap();
        assert_eq!(budget.reserved_bytes().unwrap(), 0);
        assert!(!root.0.join(".lease-dead-owner").exists());
        let link = root.0.join("link");
        std::os::unix::fs::symlink(&root.0, &link).unwrap();
        assert!(SpoolBudget::open(&link, 10, 0).is_err());
    }

    #[test]
    fn existing_data_directory_is_rejected_without_writing_control_files() {
        use std::os::unix::fs::PermissionsExt;
        let root = TestRoot::new();
        std::fs::create_dir(&root.0).unwrap();
        std::fs::set_permissions(&root.0, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(root.0.join("existing.db"), b"preserve").unwrap();
        assert!(SpoolBudget::open(&root.0, 10, 0).is_err());
        assert_eq!(
            std::fs::read(root.0.join("existing.db")).unwrap(),
            b"preserve"
        );
        assert!(!root.0.join(".lock").exists());
        assert!(!root.0.join(".limit").exists());
    }
}
