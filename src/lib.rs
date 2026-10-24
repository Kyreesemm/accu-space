//! Cross-platform disk scanning logic.
//!
//! The library deliberately has no GUI or third-party dependencies.  A future
//! desktop or web-facing application can use [`Analyzer::analyze`] and render
//! the returned data in whatever interface it needs.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const CATEGORY_DEFINITIONS: &[(&str, &[&str])] = &[
    (
        "Системные",
        &[
            "sys", "dll", "drv", "ini", "cfg", "inf", "lnk", "dmp", "tmp", "bak",
            "log", "msi", "cab", "cat", "rom", "efi", "old", "reg", "manifest",
        ],
    ),
    (
        "Программы",
        &[
            "exe", "app", "pkg", "msi", "bat", "cmd", "sh", "deb", "rpm", "msix",
            "appx", "AppImage",
        ],
    ),
    (
        "Игры",
        &[
            "iso", "rom", "nes", "gba", "sg", "bin", "cue", "vdf", "gcf", "nsp",
            "xci", "wbfs", "wad", "patch", "bik", "vpk", "pak",
        ],
    ),
    (
        "Видео",
        &[
            "mp4", "avi", "mkv", "mov", "flv", "wmv", "m4v", "3gp", "webm", "ts",
            "m2ts", "ogv", "divx", "xvid", "rm", "rmvb", "asf", "f4v",
        ],
    ),
    (
        "Музыка",
        &[
            "mp3", "wav", "flac", "aac", "ogg", "wma", "m4a", "opus", "alac",
            "m4b", "oga", "ape", "wv", "mid", "midi", "aiff", "ac3",
        ],
    ),
    (
        "Фото",
        &[
            "jpg", "jpeg", "png", "gif", "bmp", "tiff", "webp", "raw", "cr2",
            "nef", "arw", "dng", "svg", "ico", "psd", "ai", "eps", "heic", "heif",
            "xcf", "indd",
        ],
    ),
    (
        "Документы",
        &[
            "doc", "docx", "pdf", "txt", "xls", "xlsx", "ppt", "pptx", "odt",
            "rtf", "md", "epub", "mobi", "djvu", "fb2", "csv", "ods", "odp",
            "pages", "key", "numbers", "chm", "tex", "ps",
        ],
    ),
    (
        "Архивы",
        &[
            "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "lz", "dmg", "zst",
            "tgz", "tbz2", "cab", "iso", "arj", "cpio", "deb", "rpm",
        ],
    ),
    (
        "Базы данных",
        &[
            "db", "sql", "sqlite", "sqlite3", "mdb", "accdb", "json", "xml",
            "bson", "ldb", "sst", "sqlite-shm", "sqlite-wal", "myd", "myi", "frm",
        ],
    ),
    (
        "Разработка",
        &[
            "rs", "go", "ts", "js", "jsx", "tsx", "py", "c", "cpp", "h", "hpp",
            "cs", "java", "kt", "kts", "swift", "rb", "php", "lock", "toml",
            "yaml", "yml", "cmake", "vue", "svelte", "ex", "exs", "scala",
            "patch", "diff", "asm", "s", "cc", "cxx", "tsx",
        ],
    ),
    (
        "Скрипты",
        &["ps1", "vbs", "lua", "pl", "pm", "r", "jl", "bash", "zsh", "fish"],
    ),
    (
        "Веб-файлы",
        &["html", "htm", "css", "scss", "less", "sass", "wasm", "map"],
    ),
    (
        "Образы дисков",
        &["vhd", "vhdx", "img", "qcow2", "vdi", "vmdk", "toast"],
    ),
    ("Шрифты", &["ttf", "otf", "woff", "woff2", "eot", "fon", "pfb", "pfm"]),
    ("Логи", &["log", "evtx", "trace", "dump", "out", "err"]),
];

/// Filesystem capacity information for the filesystem containing the scan root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskUsage {
    pub total: u64,
    pub used: u64,
    pub free: u64,
}

/// A mounted volume that can be inspected by the analyzer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountedDisk {
    pub name: String,
    pub path: PathBuf,
    pub filesystem: String,
    pub usage: DiskUsage,
}

/// List accessible local filesystems, excluding virtual and pseudo mounts.
#[cfg(target_os = "linux")]
pub fn discover_disks() -> io::Result<Vec<MountedDisk>> {
    use std::collections::BTreeMap;
    let mounts = std::fs::read_to_string("/proc/self/mounts")?;
    let mut unique = BTreeMap::<PathBuf, MountedDisk>::new();
    for line in mounts.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 3 { continue; }
        let filesystem = fields[2];
        if matches!(filesystem, "proc" | "sysfs" | "devtmpfs" | "devpts" | "tmpfs" | "cgroup" | "cgroup2" | "securityfs" | "debugfs" | "tracefs" | "pstore" | "mqueue" | "hugetlbfs" | "fusectl" | "configfs" | "autofs" | "overlay" | "nsfs" | "rpc_pipefs") { continue; }
        let decode = |s: &str| s.replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\").replace("\\042", "\"");
        let path = PathBuf::from(decode(fields[1]));
        if !path.is_dir() { continue; }
        let Ok(usage) = disk_usage(&path) else { continue; };
        let name = path.file_name().filter(|n| !n.is_empty()).map_or_else(|| path.display().to_string(), |n| n.to_string_lossy().into_owned());
        unique.entry(path.clone()).or_insert(MountedDisk { name, path, filesystem: filesystem.to_string(), usage });
    }
    let mut result: Vec<_> = unique.into_values().collect();
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}

#[cfg(windows)]
pub fn discover_disks() -> io::Result<Vec<MountedDisk>> {
    use std::os::windows::ffi::OsStringExt;
    use std::ffi::OsString;
    unsafe extern "system" {
        fn GetLogicalDrives() -> u32;
        fn GetDriveTypeW(root: *const u16) -> u32;
    }
    let bits = unsafe { GetLogicalDrives() };
    let mut disks = Vec::new();
    for index in 0..26 {
        if bits & (1 << index) == 0 { continue; }
        let letter = char::from(b'A' + index as u8);
        let path = PathBuf::from(format!("{letter}:\\"));
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        // Skip removable optical media and disconnected/network paths; include fixed and mounted volumes.
        if !matches!(unsafe { GetDriveTypeW(wide.as_ptr()) }, 2 | 3 | 6) { continue; }
        let Ok(usage) = disk_usage(&path) else { continue; };
        let name = OsString::from_wide(&[letter as u16]).to_string_lossy().into_owned();
        disks.push(MountedDisk { name: format!("{name}:"), path, filesystem: "Том Windows".to_string(), usage });
    }
    Ok(disks)
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn discover_disks() -> io::Result<Vec<MountedDisk>> { Ok(Vec::new()) }

/// One successfully inspected file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub path: PathBuf,
    pub size: u64,
    pub category: String,
}

/// Aggregated size and count for one category.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CategorySummary {
    pub bytes: u64,
    pub files: u64,
}

/// Result of one completed analysis.
#[derive(Debug, Clone)]
pub struct AnalysisReport {
    pub root: PathBuf,
    pub disk_usage: DiskUsage,
    pub files: Vec<FileEntry>,
    pub categories: BTreeMap<String, CategorySummary>,
    pub discovered_files: usize,
    pub processed_files: usize,
    pub skipped_files: usize,
    pub elapsed: Duration,
}

impl AnalysisReport {
    /// Save report in a custom fast binary format (.dar).
    pub fn save_binary<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        // Magic bytes: DAR1 (Disk Analyzer Report v1)
        writer.write_all(b"DAR1")?;

        // Root path
        let root_str = self.root.to_string_lossy();
        let root_bytes = root_str.as_bytes();
        writer.write_all(&(root_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(root_bytes)?;

        // Disk usage
        writer.write_all(&self.disk_usage.total.to_le_bytes())?;
        writer.write_all(&self.disk_usage.used.to_le_bytes())?;
        writer.write_all(&self.disk_usage.free.to_le_bytes())?;

        // Stats
        writer.write_all(&(self.discovered_files as u64).to_le_bytes())?;
        writer.write_all(&(self.processed_files as u64).to_le_bytes())?;
        writer.write_all(&(self.skipped_files as u64).to_le_bytes())?;
        writer.write_all(&(self.elapsed.as_millis() as u64).to_le_bytes())?;

        // Categories
        writer.write_all(&(self.categories.len() as u32).to_le_bytes())?;
        for (name, summary) in &self.categories {
            let name_bytes = name.as_bytes();
            writer.write_all(&(name_bytes.len() as u32).to_le_bytes())?;
            writer.write_all(name_bytes)?;
            writer.write_all(&summary.bytes.to_le_bytes())?;
            writer.write_all(&summary.files.to_le_bytes())?;
        }

        // Files
        writer.write_all(&(self.files.len() as u64).to_le_bytes())?;
        for file_entry in &self.files {
            let path_str = file_entry.path.to_string_lossy();
            let path_bytes = path_str.as_bytes();
            writer.write_all(&(path_bytes.len() as u32).to_le_bytes())?;
            writer.write_all(path_bytes)?;
            writer.write_all(&file_entry.size.to_le_bytes())?;
            let cat_bytes = file_entry.category.as_bytes();
            writer.write_all(&(cat_bytes.len() as u32).to_le_bytes())?;
            writer.write_all(cat_bytes)?;
        }

        writer.flush()?;
        Ok(())
    }

    /// Load report from a custom fast binary format (.dar).
    pub fn load_binary<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);

        // Magic bytes
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if &magic != b"DAR1" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Неверный формат бинарного отчёта (.dar)"));
        }

        // Root path
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let root_len = u32::from_le_bytes(len_buf) as usize;
        let mut root_bytes = vec![0u8; root_len];
        reader.read_exact(&mut root_bytes)?;
        let root = PathBuf::from(String::from_utf8_lossy(&root_bytes).into_owned());

        // Disk usage
        let mut u64_buf = [0u8; 8];
        reader.read_exact(&mut u64_buf)?;
        let total = u64::from_le_bytes(u64_buf);
        reader.read_exact(&mut u64_buf)?;
        let used = u64::from_le_bytes(u64_buf);
        reader.read_exact(&mut u64_buf)?;
        let free = u64::from_le_bytes(u64_buf);
        let disk_usage = DiskUsage { total, used, free };

        // Stats
        reader.read_exact(&mut u64_buf)?;
        let discovered_files = u64::from_le_bytes(u64_buf) as usize;
        reader.read_exact(&mut u64_buf)?;
        let processed_files = u64::from_le_bytes(u64_buf) as usize;
        reader.read_exact(&mut u64_buf)?;
        let skipped_files = u64::from_le_bytes(u64_buf) as usize;
        reader.read_exact(&mut u64_buf)?;
        let elapsed_ms = u64::from_le_bytes(u64_buf);
        let elapsed = Duration::from_millis(elapsed_ms);

        // Categories
        reader.read_exact(&mut len_buf)?;
        let cat_len = u32::from_le_bytes(len_buf) as usize;
        let mut categories = BTreeMap::new();
        for _ in 0..cat_len {
            reader.read_exact(&mut len_buf)?;
            let name_len = u32::from_le_bytes(len_buf) as usize;
            let mut name_bytes = vec![0u8; name_len];
            reader.read_exact(&mut name_bytes)?;
            let name = String::from_utf8_lossy(&name_bytes).into_owned();

            reader.read_exact(&mut u64_buf)?;
            let bytes = u64::from_le_bytes(u64_buf);
            reader.read_exact(&mut u64_buf)?;
            let files_count = u64::from_le_bytes(u64_buf);

            categories.insert(name, CategorySummary { bytes, files: files_count });
        }

        // Files
        let mut u64_len_buf = [0u8; 8];
        reader.read_exact(&mut u64_len_buf)?;
        let files_len = u64::from_le_bytes(u64_len_buf) as usize;
        let mut files = Vec::with_capacity(files_len);
        for _ in 0..files_len {
            reader.read_exact(&mut len_buf)?;
            let path_len = u32::from_le_bytes(len_buf) as usize;
            let mut path_bytes = vec![0u8; path_len];
            reader.read_exact(&mut path_bytes)?;
            let path = PathBuf::from(String::from_utf8_lossy(&path_bytes).into_owned());

            reader.read_exact(&mut u64_buf)?;
            let size = u64::from_le_bytes(u64_buf);

            reader.read_exact(&mut len_buf)?;
            let cat_len = u32::from_le_bytes(len_buf) as usize;
            let mut cat_bytes = vec![0u8; cat_len];
            reader.read_exact(&mut cat_bytes)?;
            let category = String::from_utf8_lossy(&cat_bytes).into_owned();

            files.push(FileEntry { path, size, category });
        }

        Ok(AnalysisReport {
            root,
            disk_usage,
            files,
            categories,
            discovered_files,
            processed_files,
            skipped_files,
            elapsed,
        })
    }
}

/// Get the directory next to the executable for storing binary reports.
pub fn default_reports_dir() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            return parent.join("DiskReports");
        }
    }
    PathBuf::from("DiskReports")
}

/// Options controlling a scan.
#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    /// Directory or mount point to scan.
    pub root: PathBuf,
    /// Number of workers used for metadata queries. Zero means an automatic value.
    pub workers: usize,
    /// Directory names excluded at every level, compared case-insensitively.
    pub ignore_dirs: Vec<String>,
}

impl AnalyzeOptions {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            workers: 0,
            ignore_dirs: default_ignore_dirs(),
        }
    }
}

/// Progress information suitable for a future GUI or web bridge.
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    pub discovered_files: usize,
    pub processed_files: usize,
    pub skipped_files: usize,
}

/// Stateless analyzer.  Keeping it stateless makes it safe to create per-request
/// instances from a server or to run multiple independent analyses.
#[derive(Debug, Default, Clone, Copy)]
pub struct Analyzer;

impl Analyzer {
    pub fn new() -> Self {
        Self
    }

    /// Analyze a root without progress notifications.
    pub fn analyze(&self, options: &AnalyzeOptions) -> io::Result<AnalysisReport> {
        self.analyze_with_progress(options, |_| {})
    }

    /// Analyze a root and periodically report progress from worker threads.
    pub fn analyze_with_progress<F>(
        &self,
        options: &AnalyzeOptions,
        progress: F,
    ) -> io::Result<AnalysisReport>
    where
        F: Fn(Progress) + Send + Sync + 'static,
    {
        let started = Instant::now();
        let root = fs::canonicalize(&options.root).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "не удалось открыть корень '{}': {error}",
                    options.root.display()
                ),
            )
        })?;
        if !root.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("корень анализа не является папкой: {}", root.display()),
            ));
        }

        let disk_usage = disk_usage(&root)?;
        let ignored: Vec<String> = options.ignore_dirs.iter().map(|n| n.to_lowercase()).collect();

        // Phase 1: Fast directory traversal and file collection with sizes
        let mut directories = vec![root.clone()];
        let mut file_items = Vec::new();
        let mut skipped = 0usize;

        while let Some(dir) = directories.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            for item in entries {
                let item = match item {
                    Ok(i) => i,
                    Err(_) => {
                        skipped += 1;
                        continue;
                    }
                };
                let Ok(file_type) = item.file_type() else {
                    skipped += 1;
                    continue;
                };
                let name = item.file_name();
                if file_type.is_dir() {
                    if is_ignored_name(&name, &ignored) {
                        continue;
                    }
                    directories.push(item.path());
                } else if file_type.is_file() {
                    let path = item.path();
                    let size = item.metadata()
                        .map(|m| m.len())
                        .or_else(|_| fs::metadata(&path).map(|m| m.len()));
                    match size {
                        Ok(size) => file_items.push((path, size)),
                        Err(_) => skipped += 1,
                    }
                }
            }
        }

        let discovered_files = file_items.len();
        let workers = worker_count(options.workers, discovered_files);
        let queue = Arc::new(Mutex::new(VecDeque::from(file_items)));
        let files = Arc::new(Mutex::new(Vec::with_capacity(discovered_files)));
        let processed = Arc::new(AtomicUsize::new(0));
        let progress = Arc::new(progress);
        let skipped_atomic = Arc::new(AtomicUsize::new(skipped));

        // Initial progress report with total discovered files
        progress(Progress {
            discovered_files,
            processed_files: 0,
            skipped_files: skipped,
        });

        // Phase 2: Parallel categorization and aggregation
        thread::scope(|scope| {
            for _ in 0..workers {
                let queue = Arc::clone(&queue);
                let files = Arc::clone(&files);
                let processed = Arc::clone(&processed);
                let skipped_atomic = Arc::clone(&skipped_atomic);
                let progress = Arc::clone(&progress);

                scope.spawn(move || {
                    let mut local_entries = Vec::with_capacity(256);
                    let mut local_processed = 0usize;

                    loop {
                        let item = {
                            let mut q = queue.lock().unwrap();
                            q.pop_front()
                        };
                        let Some((path, size)) = item else { break };

                        let category = category_for_path(&path);
                        local_entries.push(FileEntry { path, size, category });
                        local_processed += 1;

                        if local_entries.len() >= 128 {
                            let mut f = files.lock().unwrap();
                            f.append(&mut local_entries);
                            let done = processed.fetch_add(local_processed, Ordering::Relaxed) + local_processed;
                            local_processed = 0;
                            if done.is_multiple_of(100) || done == discovered_files {
                                progress(Progress {
                                    discovered_files,
                                    processed_files: done,
                                    skipped_files: skipped_atomic.load(Ordering::Relaxed),
                                });
                            }
                        }
                    }

                    if !local_entries.is_empty() || local_processed > 0 {
                        let mut f = files.lock().unwrap();
                        f.append(&mut local_entries);
                        let done = processed.fetch_add(local_processed, Ordering::Relaxed) + local_processed;
                        progress(Progress {
                            discovered_files,
                            processed_files: done,
                            skipped_files: skipped_atomic.load(Ordering::Relaxed),
                        });
                    }
                });
            }
        });

        let mut files = Arc::try_unwrap(files)
            .map_err(|_| io::Error::other("ошибка завершения рабочих потоков"))?
            .into_inner()
            .map_err(|_| io::Error::other("ошибка чтения результатов анализа"))?;

        files.sort_by(|left, right| left.path.cmp(&right.path));

        let mut categories = BTreeMap::new();
        for entry in &files {
            let summary = categories
                .entry(entry.category.clone())
                .or_insert(CategorySummary::default());
            summary.bytes = summary.bytes.saturating_add(entry.size);
            summary.files += 1;
        }

        let processed_count = processed.load(Ordering::Relaxed);
        let skipped_count = skipped_atomic.load(Ordering::Relaxed);

        let report = AnalysisReport {
            root,
            disk_usage,
            files,
            categories,
            discovered_files,
            processed_files: processed_count,
            skipped_files: skipped_count,
            elapsed: started.elapsed(),
        };
        progress(Progress {
            discovered_files: report.discovered_files,
            processed_files: report.processed_files,
            skipped_files: report.skipped_files,
        });
        Ok(report)
    }
}

fn worker_count(requested: usize, files: usize) -> usize {
    if files == 0 {
        return 1;
    }
    let automatic =
        thread::available_parallelism().map_or(4, |count| count.get().saturating_mul(2));
    requested
        .max(1)
        .min(if requested == 0 { automatic } else { requested })
        .min(files)
}

fn is_ignored_name(name: &OsString, ignored: &[String]) -> bool {
    let name = name.to_string_lossy().to_lowercase();
    ignored.iter().any(|candidate| candidate == &name)
}

/// Return the category used by the original analyzer for a path.
pub fn category_for_path(path: &Path) -> String {
    let path_str = path.to_string_lossy().to_lowercase();

    // 1. Steam / Games detection (SteamLibrary / steamapps gives exact game size)
    if path_str.contains("steamlibrary") || path_str.contains("steamapps") {
        return "Игры".to_string();
    }

    // 2. Development detection (directories, config files, source code extensions)
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_lowercase();

    if matches!(
        file_name.as_str(),
        "dockerfile"
            | "containerfile"
            | "makefile"
            | "rakefile"
            | "gemfile"
            | "vagrantfile"
            | "docker-compose.yml"
            | "docker-compose.yaml"
            | "container-compose.yml"
            | ".gitignore"
            | ".gitattributes"
            | ".env"
            | "cargo.toml"
            | "cargo.lock"
            | "package.json"
            | "tsconfig.json"
    )
        || path_str.contains("node_modules")
        || path_str.contains("/.git/")
        || path_str.contains("\\.git\\")
        || path_str.contains("target/debug")
        || path_str.contains("target/release")
        || path_str.contains(".vscode")
        || path_str.contains(".idea")
        || path_str.contains("venv")
        || path_str.contains(".venv")
        || path_str.contains("__pycache__")
    {
        return "Разработка".to_string();
    }

    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_lowercase();

    let dev_extensions = [
        "rs", "go", "ts", "js", "jsx", "tsx", "py", "c", "cpp", "h", "hpp",
        "cs", "java", "kt", "kts", "swift", "rb", "php", "lock", "toml",
        "yaml", "yml", "cmake", "vue", "svelte",
    ];
    if dev_extensions.iter().any(|&ext| ext == extension) {
        return "Разработка".to_string();
    }

    for (category, extensions) in CATEGORY_DEFINITIONS {
        if extensions.iter().any(|candidate| *candidate == extension) {
            return (*category).to_string();
        }
    }

    if path_str.contains("game") {
        "Игры".to_string()
    } else {
        "Другое".to_string()
    }
}

pub fn default_ignore_dirs() -> Vec<String> {
    if cfg!(windows) {
        [
            "windows",
            "program files",
            "program files (x86)",
            "programdata",
            "appdata",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    } else {
        ["proc", "sys", "dev", "run"]
            .into_iter()
            .map(str::to_string)
            .collect()
    }
}

/// Write a human-readable report compatible with the old report layout.
pub fn write_report(report: &AnalysisReport, output_dir: &Path) -> io::Result<()> {
    fs::create_dir_all(output_dir)?;
    write_summary_json(report, &output_dir.join("summary.json"))?;

    for category in report.categories.keys() {
        let category_dir = output_dir.join(sanitize_filename(category));
        fs::create_dir_all(&category_dir)?;
        let mut category_files: Vec<&FileEntry> = report
            .files
            .iter()
            .filter(|file| file.category == *category)
            .collect();
        category_files.sort_by(|left, right| {
            right
                .size
                .cmp(&left.size)
                .then_with(|| left.path.cmp(&right.path))
        });

        let mut top = BufWriter::new(File::create(category_dir.join("top_files.txt"))?);
        for file in category_files.iter().take(100) {
            writeln!(top, "{} - {}", format_size(file.size), file.path.display())?;
        }

        let mut all = BufWriter::new(File::create(category_dir.join("all_files.json"))?);
        writeln!(all, "[")?;
        for (index, file) in category_files.iter().enumerate() {
            let comma = if index + 1 == category_files.len() {
                ""
            } else {
                ","
            };
            writeln!(
                all,
                "  {{\"path\":{},\"size\":{}}}{comma}",
                json_string(&file.path.to_string_lossy()),
                file.size
            )?;
        }
        writeln!(all, "]")?;
    }
    Ok(())
}

fn write_summary_json(report: &AnalysisReport, path: &Path) -> io::Result<()> {
    let mut output = BufWriter::new(File::create(path)?);
    writeln!(output, "{{")?;
    writeln!(output, "  \"disk_info\": {{")?;
    writeln!(
        output,
        "    \"root\": {},",
        json_string(&report.root.to_string_lossy())
    )?;
    writeln!(output, "    \"total\": {},", report.disk_usage.total)?;
    writeln!(output, "    \"used\": {},", report.disk_usage.used)?;
    writeln!(output, "    \"free\": {}", report.disk_usage.free)?;
    writeln!(output, "  }},")?;
    writeln!(
        output,
        "  \"scan\": {{\"discovered_files\":{},\"processed_files\":{},\"skipped_files\":{},\"elapsed_ms\":{}}},",
        report.discovered_files,
        report.processed_files,
        report.skipped_files,
        report.elapsed.as_millis()
    )?;
    writeln!(output, "  \"categories\": {{")?;
    for (index, (category, summary)) in report.categories.iter().enumerate() {
        let comma = if index + 1 == report.categories.len() {
            ""
        } else {
            ","
        };
        writeln!(
            output,
            "    {}: {{\"bytes\":{},\"files\":{}}}{comma}",
            json_string(category),
            summary.bytes,
            summary.files
        )?;
    }
    writeln!(output, "  }}")?;
    writeln!(output, "}}")?;
    Ok(())
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32))
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

fn sanitize_filename(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|character| {
            if "<>:\"/\\|?*".contains(character) {
                '_'
            } else {
                character
            }
        })
        .collect();
    if sanitized.is_empty() {
        "Без категории".to_string()
    } else {
        sanitized
    }
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    let mut unit = 0;
    let mut value = bytes as f64;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

#[cfg(unix)]
#[allow(clippy::unnecessary_cast)] // c_ulong is 32-bit on some supported Unix targets.
fn disk_usage(path: &Path) -> io::Result<DiskUsage> {
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int, c_ulong};
    use std::os::unix::ffi::OsStrExt;

    #[repr(C)]
    struct Statvfs {
        f_bsize: c_ulong,
        f_frsize: c_ulong,
        f_blocks: c_ulong,
        f_bfree: c_ulong,
        f_bavail: c_ulong,
        f_files: c_ulong,
        f_ffree: c_ulong,
        f_favail: c_ulong,
        f_fsid: c_ulong,
        f_flag: c_ulong,
        f_namemax: c_ulong,
        f_spare: [c_int; 6],
    }

    unsafe extern "C" {
        fn statvfs(path: *const c_char, buffer: *mut Statvfs) -> c_int;
    }
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "путь содержит нулевой байт"))?;
    let mut stats = std::mem::MaybeUninit::<Statvfs>::uninit();
    // SAFETY: `path` is a valid NUL-terminated string and `stats` points to writable memory.
    let result = unsafe { statvfs(path.as_ptr(), stats.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: statvfs initialized the structure on success.
    let stats = unsafe { stats.assume_init() };
    let block_size = if stats.f_frsize == 0 {
        stats.f_bsize
    } else {
        stats.f_frsize
    } as u64;
    let total = (stats.f_blocks as u64).saturating_mul(block_size);
    let free = (stats.f_bavail as u64)
        .saturating_mul(block_size)
        .min(total);
    Ok(DiskUsage {
        total,
        used: total - free,
        free,
    })
}

#[cfg(windows)]
fn disk_usage(path: &Path) -> io::Result<DiskUsage> {
    use std::os::windows::ffi::OsStrExt;

    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(
            path: *const u16,
            available: *mut u64,
            total: *mut u64,
            free: *mut u64,
        ) -> i32;
    }
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let mut available = 0;
    let mut total = 0;
    let mut _free = 0;
    // SAFETY: the path is NUL-terminated and all output pointers are valid.
    let result =
        unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut available, &mut total, &mut _free) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    let free = available.min(total);
    Ok(DiskUsage {
        total,
        used: total - free,
        free,
    })
}

#[cfg(not(any(unix, windows)))]
fn disk_usage(_path: &Path) -> io::Result<DiskUsage> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "эта операционная система не поддерживается",
    ))
}

/// An item of discovered system trash, cache, or development junk.
#[derive(Debug, Clone)]
pub struct TrashItem {
    pub key: String,
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
    pub file_count: u64,
    pub category: String,
    pub description: String,
}

/// Calculate directory size and file count recursively.
pub fn calculate_dir_size(path: &Path) -> (u64, u64) {
    let mut total_bytes = 0;
    let mut file_count = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else { continue; };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue; };
            let p = entry.path();
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                if let Ok(meta) = entry.metadata() {
                    total_bytes += meta.len();
                    file_count += 1;
                }
            }
        }
    }
    (total_bytes, file_count)
}

/// Delete path contents (file or directory recursively) and return (bytes_freed, files_deleted).
pub fn delete_path_contents(path: &Path) -> io::Result<(u64, u64)> {
    let mut bytes_freed = 0;
    let mut files_deleted = 0;
    if path.is_file() {
        if let Ok(meta) = fs::metadata(path) {
            bytes_freed = meta.len();
            files_deleted = 1;
        }
        fs::remove_file(path)?;
        return Ok((bytes_freed, files_deleted));
    }
    if path.is_dir() {
        let (b, c) = calculate_dir_size(path);
        bytes_freed = b;
        files_deleted = c;
        fs::remove_dir_all(path)?;
    }
    Ok((bytes_freed, files_deleted))
}

/// Scan system trash, temporary folders, browser caches, and development artifacts.
pub fn scan_trash() -> io::Result<Vec<TrashItem>> {
    let mut items = Vec::new();

    #[cfg(target_os = "linux")]
    {
        push_trash_item(&mut items, "linux_tmp", "Временные файлы (/tmp)", PathBuf::from("/tmp"), "Системный мусор", "Файлы во временной директории системы");
        push_trash_item(&mut items, "linux_var_tmp", "Временные файлы (/var/tmp)", PathBuf::from("/var/tmp"), "Системный мусор", "Долгоживущие временные файлы");

        if let Ok(home) = std::env::var("HOME").map(PathBuf::from) {
            push_trash_item(&mut items, "user_cache", "Пользовательский кэш (~/.cache)", home.join(".cache"), "Кэш", "Общий кэш приложений");
            push_trash_item(&mut items, "user_trash", "Корзина (~/.local/share/Trash)", home.join(".local/share/Trash"), "Корзина", "Удаленные файлы, ожидающие очистки");
            push_trash_item(&mut items, "thumbnails", "Кэш миниатюр (~/.cache/thumbnails)", home.join(".cache/thumbnails"), "Кэш", "Предпросмотр изображений и видео");
            push_trash_item(&mut items, "yay_cache", "Кэш AUR (yay)", home.join(".cache/yay"), "Пакеты", "Загруженные пакеты и исходники AUR");
            push_trash_item(&mut items, "paru_cache", "Кэш AUR (paru)", home.join(".cache/paru"), "Пакеты", "Загруженные пакеты и исходники AUR");
            push_trash_item(&mut items, "cargo_cache", "Кэш Cargo (~/.cargo/registry)", home.join(".cargo/registry/cache"), "Разработка", "Загруженные зависимости Rust");
            push_trash_item(&mut items, "npm_cache", "Кэш npm (~/.npm)", home.join(".npm"), "Разработка", "Кэш пакетного менеджера Node.js");
            push_trash_item(&mut items, "pip_cache", "Кэш pip (~/.cache/pip)", home.join(".cache/pip"), "Разработка", "Кэш пакетов Python");

            let dev_roots = vec![
                home.join("Projects"),
                home.join("Dev"),
                home.join("Workspace"),
                home.join("Documents"),
                home.join("Downloads"),
            ];
            for dev_root in dev_roots {
                if dev_root.is_dir() {
                    scan_dev_junk(&dev_root, &mut items);
                }
            }
        }

        let pacman_cache = PathBuf::from("/var/cache/pacman/pkg");
        if pacman_cache.is_dir() {
            push_trash_item(&mut items, "pacman_cache", "Кэш Pacman (/var/cache/pacman/pkg)", pacman_cache, "Пакеты", "Установленные и старые версии пакетов Arch Linux");
        }
        let apt_cache = PathBuf::from("/var/cache/apt/archives");
        if apt_cache.is_dir() {
            push_trash_item(&mut items, "apt_cache", "Кэш APT (/var/cache/apt/archives)", apt_cache, "Пакеты", "Загруженные пакеты Debian/Ubuntu");
        }
    }

    #[cfg(windows)]
    {
        if let Ok(windir) = std::env::var("SystemRoot").map(PathBuf::from) {
            push_trash_item(&mut items, "win_temp", "Временные файлы Windows", windir.join("Temp"), "Системный мусор", "Системный кэш и временные файлы");
            push_trash_item(&mut items, "win_update", "Кэш обновлений Windows", windir.join("SoftwareDistribution\\Download"), "Системный мусор", "Загруженные обновления Windows");
        }
        if let Ok(local_appdata) = std::env::var("LOCALAPPDATA").map(PathBuf::from) {
            push_trash_item(&mut items, "user_temp", "Временные файлы пользователя", local_appdata.join("Temp"), "Системный мусор", "Временные файлы приложений пользователя");
            push_trash_item(&mut items, "win_explorer_cache", "Кэш иконок и миниатюр", local_appdata.join("Microsoft\\Windows\\Explorer"), "Кэш", "Базы данных миниатюр проводника");
            push_trash_item(&mut items, "nuget_cache", "Кэш NuGet", local_appdata.join("NuGet\\Cache"), "Разработка", "Кэш пакетов .NET");
        }
        if let Ok(profile) = std::env::var("USERPROFILE").map(PathBuf::from) {
            let dev_roots = vec![
                profile.join("Source"),
                profile.join("Projects"),
                profile.join("Dev"),
                profile.join("Documents"),
            ];
            for dev_root in dev_roots {
                if dev_root.is_dir() {
                    scan_dev_junk(&dev_root, &mut items);
                }
            }
        }
    }

    Ok(items)
}

fn push_trash_item(items: &mut Vec<TrashItem>, key: &str, name: &str, path: PathBuf, category: &str, desc: &str) {
    if path.exists() {
        let (size, file_count) = calculate_dir_size(&path);
        if size > 0 || path.is_dir() {
            items.push(TrashItem {
                key: key.to_string(),
                name: name.to_string(),
                path,
                size,
                file_count,
                category: category.to_string(),
                description: desc.to_string(),
            });
        }
    }
}

fn scan_dev_junk(root: &Path, items: &mut Vec<TrashItem>) {
    let mut directories = vec![root.to_path_buf()];
    let mut count = 0;
    while let Some(dir) = directories.pop() {
        count += 1;
        if count > 5000 { break; }
        let Ok(entries) = fs::read_dir(&dir) else { continue; };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue; };
            if ft.is_dir() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if matches!(name_str.as_ref(), "node_modules" | "target" | "__pycache__" | ".pytest_cache" | ".mypy_cache" | "venv" | ".venv" | "env" | "dist" | "build" | ".next" | ".nuxt") {
                    let path = entry.path();
                    let (size, file_count) = calculate_dir_size(&path);
                    if size > 0 {
                        let key = format!("dev_{}", path.to_string_lossy());
                        let parent_name = entry.path().parent().and_then(|p| p.file_name()).map_or("".to_string(), |n| n.to_string_lossy().into_owned());
                        items.push(TrashItem {
                            key,
                            name: format!("{} ({})", name_str, parent_name),
                            path,
                            size,
                            file_count,
                            category: "Разработка (артефакты)".to_string(),
                            description: format!("Директория {} в проекте", name_str),
                        });
                    }
                } else if !matches!(name_str.as_ref(), ".git" | ".idea" | ".vscode") {
                    directories.push(entry.path());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_are_case_insensitive_and_preserve_game_fallback() {
        assert_eq!(category_for_path(Path::new("photo.JpG")), "Фото");
        assert_eq!(category_for_path(Path::new("my-game/data.binx")), "Игры");
        assert_eq!(category_for_path(Path::new("notes.unknown")), "Другое");
    }

    #[test]
    fn size_format_uses_binary_units() {
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1024 * 1024), "1.00 MB");
    }

    #[test]
    fn json_escaping_is_valid_for_basic_special_characters() {
        assert_eq!(json_string("a\\b\"c\n"), "\"a\\\\b\\\"c\\n\"");
    }

    #[test]
    fn binary_report_roundtrip() {
        let root = std::env::temp_dir();
        let report = AnalysisReport {
            root: root.clone(),
            disk_usage: DiskUsage { total: 100, used: 50, free: 50 },
            files: vec![
                FileEntry {
                    path: root.join("test.txt"),
                    size: 10,
                    category: "Документы".to_string(),
                }
            ],
            categories: {
                let mut map = BTreeMap::new();
                map.insert("Документы".to_string(), CategorySummary { bytes: 10, files: 1 });
                map
            },
            discovered_files: 1,
            processed_files: 1,
            skipped_files: 0,
            elapsed: Duration::from_secs(1),
        };

        let temp_dar = root.join("test_report.dar");
        report.save_binary(&temp_dar).unwrap();
        let loaded = AnalysisReport::load_binary(&temp_dar).unwrap();
        assert_eq!(loaded.root, report.root);
        assert_eq!(loaded.disk_usage, report.disk_usage);
        assert_eq!(loaded.files.len(), 1);
        assert_eq!(loaded.files[0].size, 10);
        let _ = fs::remove_file(temp_dar);
    }

    #[test]
    fn analyze_collects_files_and_writes_report() {
        let root = std::env::temp_dir().join(format!(
            "disk-analyzer-test-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::create_dir_all(root.join("ignored")).unwrap();
        fs::write(root.join("photo.JPG"), vec![0_u8; 3]).unwrap();
        fs::write(root.join("nested/readme.txt"), vec![0_u8; 5]).unwrap();
        fs::write(root.join("ignored/secret.bin"), vec![0_u8; 9]).unwrap();

        let mut options = AnalyzeOptions::new(&root);
        options.ignore_dirs = vec!["ignored".to_string()];
        options.workers = 2;
        let report = Analyzer::new().analyze(&options).unwrap();
        assert_eq!(report.processed_files, 2);
        assert_eq!(report.categories["Фото"].bytes, 3);
        assert_eq!(report.categories["Документы"].bytes, 5);

        let output = root.join("report");
        write_report(&report, &output).unwrap();
        let summary = fs::read_to_string(output.join("summary.json")).unwrap();
        assert!(summary.contains("\"Фото\""));
        assert!(output.join("Фото/top_files.txt").is_file());
        fs::remove_dir_all(root).unwrap();
    }
}
