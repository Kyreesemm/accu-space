//! Cross-platform disk scanning logic.
//!
//! The library deliberately has no GUI or third-party dependencies.  A future
//! desktop or web-facing application can use [`Analyzer::analyze`] and render
//! the returned data in whatever interface it needs.

use std::collections::{BTreeMap, VecDeque};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const CATEGORY_DEFINITIONS: &[(&str, &[&str])] = &[
    (
        "Системные",
        &[
            "sys", "dll", "drv", "ini", "cfg", "inf", "lnk", "dmp", "tmp", "bak", "log", "msi",
        ],
    ),
    (
        "Программы",
        &["exe", "app", "pkg", "msi", "bat", "cmd", "sh"],
    ),
    (
        "Игры",
        &[
            "iso", "rom", "nes", "gba", "sg", "bin", "cue", "vdf", "gcf", "nsp", "xci",
        ],
    ),
    (
        "Видео",
        &[
            "mp4", "avi", "mkv", "mov", "flv", "wmv", "m4v", "3gp", "webm", "ts",
        ],
    ),
    (
        "Музыка",
        &["mp3", "wav", "flac", "aac", "ogg", "wma", "m4a", "opus"],
    ),
    (
        "Фото",
        &[
            "jpg", "jpeg", "png", "gif", "bmp", "tiff", "webp", "raw", "cr2", "nef",
        ],
    ),
    (
        "Документы",
        &[
            "doc", "docx", "pdf", "txt", "xls", "xlsx", "ppt", "pptx", "odt", "rtf", "md",
        ],
    ),
    (
        "Архивы",
        &["zip", "rar", "7z", "tar", "gz", "bz2", "xz", "lz", "dmg"],
    ),
    (
        "Базы данных",
        &["db", "sql", "csv", "sqlite", "mdb", "accdb", "json", "xml"],
    ),
    (
        "Скрипты",
        &["py", "js", "ps1", "vbs", "php", "java", "c", "cpp", "h"],
    ),
    ("Веб-файлы", &["html", "htm", "css", "scss", "less", "sass"]),
    (
        "Образы дисков",
        &["vhd", "vhdx", "img", "qcow2", "vdi", "vmdk"],
    ),
    ("Шрифты", &["ttf", "otf", "woff", "woff2", "eot", "fon"]),
    ("Логи", &["log", "evtx", "trace"]),
];

/// Filesystem capacity information for the filesystem containing the scan root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskUsage {
    pub total: u64,
    pub used: u64,
    pub free: u64,
}

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
        let (paths, skipped_during_walk) = collect_file_paths(&root, &options.ignore_dirs)?;
        let discovered_files = paths.len();
        let workers = worker_count(options.workers, discovered_files);
        let queue = Arc::new(Mutex::new(VecDeque::from(paths)));
        let files = Arc::new(Mutex::new(Vec::with_capacity(discovered_files)));
        let skipped = Arc::new(AtomicUsize::new(skipped_during_walk));
        let processed = Arc::new(AtomicUsize::new(0));
        let progress: Arc<dyn Fn(Progress) + Send + Sync> = Arc::new(progress);

        thread::scope(|scope| {
            for _ in 0..workers {
                let queue = Arc::clone(&queue);
                let files = Arc::clone(&files);
                let skipped = Arc::clone(&skipped);
                let processed = Arc::clone(&processed);
                let progress = Arc::clone(&progress);
                scope.spawn(move || {
                    loop {
                        let path = queue.lock().expect("path queue mutex poisoned").pop_front();
                        let Some(path) = path else { break };
                        match inspect_file(path) {
                            Ok(entry) => {
                                files.lock().expect("result mutex poisoned").push(entry);
                            }
                            Err(_) => {
                                skipped.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        let done = processed.fetch_add(1, Ordering::Relaxed) + 1;
                        if done.is_multiple_of(100) || done == discovered_files {
                            progress(Progress {
                                discovered_files,
                                processed_files: done,
                                skipped_files: skipped.load(Ordering::Relaxed),
                            });
                        }
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

        let report = AnalysisReport {
            root,
            disk_usage,
            files,
            categories,
            discovered_files,
            processed_files: processed.load(Ordering::Relaxed),
            skipped_files: skipped.load(Ordering::Relaxed),
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

fn collect_file_paths(root: &Path, ignored: &[String]) -> io::Result<(Vec<PathBuf>, usize)> {
    let ignored: Vec<String> = ignored.iter().map(|name| name.to_lowercase()).collect();
    let mut directories = vec![root.to_path_buf()];
    let mut paths = Vec::new();
    let mut skipped = 0;
    while let Some(directory) = directories.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        for item in entries {
            let item = match item {
                Ok(item) => item,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            let file_type = match item.file_type() {
                Ok(file_type) => file_type,
                Err(_) => {
                    skipped += 1;
                    continue;
                }
            };
            let name = item.file_name();
            if file_type.is_dir() {
                if is_ignored_name(&name, &ignored) {
                    continue;
                }
                directories.push(item.path());
            } else if file_type.is_file() {
                paths.push(item.path());
            }
        }
    }
    Ok((paths, skipped))
}

fn is_ignored_name(name: &OsString, ignored: &[String]) -> bool {
    let name = name.to_string_lossy().to_lowercase();
    ignored.iter().any(|candidate| candidate == &name)
}

fn inspect_file(path: PathBuf) -> io::Result<FileEntry> {
    let size = fs::metadata(&path)?.len();
    let category = category_for_path(&path);
    Ok(FileEntry {
        path,
        size,
        category,
    })
}

/// Return the category used by the original analyzer for a path.
pub fn category_for_path(path: &Path) -> String {
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_lowercase();
    for (category, extensions) in CATEGORY_DEFINITIONS {
        if extensions.iter().any(|candidate| *candidate == extension) {
            return (*category).to_string();
        }
    }
    if path.to_string_lossy().to_lowercase().contains("game") {
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
