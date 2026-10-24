use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use disk_analyzer::{
    AnalysisReport, AnalyzeOptions, Analyzer, Progress, discover_disks, format_size, write_report,
};
use slint::{ModelRc, SharedString, VecModel};

slint::include_modules!();

fn main() {
    if let Err(error) = run() {
        eprintln!("Ошибка: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if arguments
        .iter()
        .any(|argument| argument == "--help" || argument == "-h")
    {
        print_help();
        return Ok(());
    }

    if arguments.is_empty() {
        return run_gui();
    }

    let mut root = PathBuf::from(".");
    let mut report_dir = None;
    let mut workers = 0;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--root" | "-r" => {
                index += 1;
                root = PathBuf::from(
                    arguments
                        .get(index)
                        .ok_or_else(|| missing_value("--root"))?,
                );
            }
            "--report-dir" => {
                index += 1;
                report_dir = Some(PathBuf::from(
                    arguments
                        .get(index)
                        .ok_or_else(|| missing_value("--report-dir"))?,
                ));
            }
            "--workers" => {
                index += 1;
                workers = arguments
                    .get(index)
                    .ok_or_else(|| missing_value("--workers"))?
                    .parse()
                    .map_err(|_| invalid_value("--workers"))?;
                if workers == 0 {
                    return Err(invalid_value("--workers должен быть больше нуля"));
                }
            }
            unknown => return Err(invalid_value(&format!("неизвестный аргумент '{unknown}'"))),
        }
        index += 1;
    }

    let mut options = AnalyzeOptions::new(root);
    options.workers = workers;
    let analyzer = Analyzer::new();
    let progress = Arc::new(move |value: Progress| {
        if value.discovered_files > 0 {
            eprintln!(
                "Анализ: {}/{} файлов",
                value.processed_files, value.discovered_files
            );
        }
    });
    let report = analyzer.analyze_with_progress(&options, move |value| progress(value))?;
    let destination = report_dir.unwrap_or_else(|| default_report_dir(&report.root));
    write_report(&report, &destination)?;

    println!("Анализ завершён за {:.2} с", report.elapsed.as_secs_f64());
    println!("Корень: {}", report.root.display());
    println!(
        "Файлов: {}, пропущено: {}",
        report.processed_files, report.skipped_files
    );
    println!(
        "Диск: {} всего, {} занято, {} свободно",
        format_size(report.disk_usage.total),
        format_size(report.disk_usage.used),
        format_size(report.disk_usage.free)
    );
    println!(
        "Отчёт: {}",
        destination.canonicalize().unwrap_or(destination).display()
    );
    let mut categories: Vec<_> = report.categories.iter().collect();
    categories.sort_by(|(_, left), (_, right)| right.bytes.cmp(&left.bytes));
    for (category, summary) in categories {
        println!(
            "  {category}: {}, {} файлов",
            format_size(summary.bytes),
            summary.files
        );
    }
    Ok(())
}

fn run_gui() -> io::Result<()> {
    let app = MainWindow::new().map_err(|error| io::Error::other(error.to_string()))?;
    let ui = app.as_weak();
    let tree_expanded = Arc::new(std::sync::Mutex::new(BTreeSet::<String>::new()));
    let toggle_ui = ui.clone();
    let toggle_expanded = tree_expanded.clone();
    app.on_toggle_tree_row(move |name| {
        let mut expanded = toggle_expanded.lock().expect("tree expansion lock poisoned");
        let key = name.to_string();
        if !expanded.insert(key.clone()) { expanded.remove(&key); }
        let rows = TREE_CACHE.with(|cache| cache.borrow().clone());
        if let Some(window) = toggle_ui.upgrade() {
            let mut visible = Vec::new();
            if let Some(tree) = rows { flatten_tree(&tree, 0, String::new(), &mut visible, &expanded); }
            window.set_tree_rows(ModelRc::from(std::rc::Rc::new(VecModel::from(visible))));
        }
    });
    let refresh_ui = ui.clone();
    app.on_refresh_disks(move || refresh_disk_rows(&refresh_ui));
    refresh_disk_rows(&ui);
    let browse_ui = ui.clone();
    app.on_choose_folder(move || {
        if let Some(path) = rfd::FileDialog::new().pick_folder()
            && let Some(ui) = browse_ui.upgrade()
        {
            ui.set_root_path(path.to_string_lossy().into_owned().into());
        }
    });

    let scan_ui = ui.clone();
    app.on_start_analysis(move || {
        let Some(window) = scan_ui.upgrade() else {
            return;
        };
        let root = PathBuf::from(window.get_root_path().to_string());
        if root.as_os_str().is_empty() {
            window.set_status_text("Укажите папку для анализа".into());
            return;
        }
        window.set_status_text("Анализ выполняется…".into());
        window.set_progress_value(0);
        window.set_progress_text("Подготовка дерева файлов…".into());
        window.set_category_rows(ModelRc::from(std::rc::Rc::new(VecModel::from(Vec::<
            CategoryRow,
        >::new(
        )))));
        window.set_tree_rows(ModelRc::from(std::rc::Rc::new(VecModel::from(Vec::<
            TreeRow,
        >::new(
        )))));
        window.set_tiles(ModelRc::from(std::rc::Rc::new(VecModel::from(
            Vec::<Tile>::new(),
        ))));

        let weak = scan_ui.clone();
        let report_dir = default_report_dir(&root);
        std::thread::spawn(move || {
            let progress_ui = weak.clone();
            let progress = move |value: Progress| {
                let ui = progress_ui.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = ui.upgrade() {
                        let percent = if value.discovered_files == 0 {
                            0
                        } else {
                            ((value.processed_files.saturating_mul(100) / value.discovered_files)
                                .min(100)) as i32
                        };
                        window.set_progress_value(percent);
                        window.set_progress_text(
                            format!(
                                "Обработано {} из {} файлов · пропущено {}",
                                value.processed_files, value.discovered_files, value.skipped_files
                            )
                            .into(),
                        );
                    }
                });
            };
            let mut options = AnalyzeOptions::new(root);
            options.workers = 0;
            let result = Analyzer::new().analyze_with_progress(&options, progress);
            if let Ok(report) = &result {
                let bin_reports_dir = disk_analyzer::default_reports_dir();
                let _ = std::fs::create_dir_all(&bin_reports_dir);
                let label = report.root.file_name().and_then(|n| n.to_str()).unwrap_or("scan");
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let dar_path = bin_reports_dir.join(format!("{label}_{timestamp}.dar"));
                let _ = report.save_binary(&dar_path);

                if let Err(error) = write_report(report, &report_dir) {
                    let ui = weak.clone();
                    let message = format!("Анализ готов, но текстовый отчёт не сохранён: {error}");
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(window) = ui.upgrade() {
                            window.set_status_text(message.into());
                        }
                    });
                    return;
                }
            }
            let ui = weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(window) = ui.upgrade() {
                    match result {
                        Ok(report) => display_report(&window, &report, &report_dir),
                        Err(error) => {
                            window.set_status_text(format!("Ошибка анализа: {error}").into());
                            window.set_progress_text("Проверьте путь и права доступа".into());
                        }
                    }
                }
            });
        });
    });

    let report_root = ui.clone();
    app.on_open_report(move || {
        if let Some(window) = report_root.upgrade() {
            let reports_dir = disk_analyzer::default_reports_dir();
            let _ = std::fs::create_dir_all(&reports_dir);
            if let Some(path) = rfd::FileDialog::new()
                .set_directory(&reports_dir)
                .add_filter("Бинарные отчёты диска", &["dar"])
                .pick_file()
            {
                match AnalysisReport::load_binary(&path) {
                    Ok(report) => {
                        display_report(&window, &report, &path);
                        window.set_status_text(SharedString::from(format!("Открыт отчёт: {}", path.display())));
                    }
                    Err(error) => {
                        window.set_status_text(SharedString::from(format!("Не удалось открыть бинарный отчёт: {error}")));
                    }
                }
            }
        }
    });

    app.run()
        .map_err(|error| io::Error::other(error.to_string()))
}

fn refresh_disk_rows(ui: &slint::Weak<MainWindow>) {
    if let Some(window) = ui.upgrade() {
        match discover_disks() {
            Ok(disks) => {
                let rows = disks.into_iter().map(|disk| DiskRow {
                    name: disk.name.into(),
                    path: disk.path.to_string_lossy().into_owned().into(),
                    kind: disk.filesystem.into(),
                    total: format!("{} всего", format_size(disk.usage.total)).into(),
                    used: format!("{} занято", format_size(disk.usage.used)).into(),
                    free: format!("{} свободно", format_size(disk.usage.free)).into(),
                    used_ratio: if disk.usage.total == 0 { 0.0 } else { disk.usage.used as f32 / disk.usage.total as f32 },
                }).collect::<Vec<_>>();
                window.set_disks(ModelRc::from(std::rc::Rc::new(VecModel::from(rows))));
            }
            Err(error) => window.set_status_text(format!("Не удалось получить список дисков: {error}").into()),
        }
    }
}

thread_local! { static TREE_CACHE: std::cell::RefCell<Option<TreeNode>> = const { std::cell::RefCell::new(None) }; }

fn display_report(window: &MainWindow, report: &AnalysisReport, report_dir: &std::path::Path) {
    window.set_status_text(format!("Готово · отчёт: {}", report_dir.display()).into());
    window.set_disk_text(
        format!(
            "{} всего · {} занято · {} свободно",
            format_size(report.disk_usage.total),
            format_size(report.disk_usage.used),
            format_size(report.disk_usage.free)
        )
        .into(),
    );
    window.set_files_text(
        format!(
            "{} файлов · пропущено {}",
            report.processed_files, report.skipped_files
        )
        .into(),
    );
    window.set_elapsed_text(format_duration(report.elapsed).into());
    window.set_progress_value(100);
    window.set_progress_text(format!("Обработано {} файлов", report.processed_files).into());
    window.set_scanned_root(report.root.to_string_lossy().into_owned().into());
    let total = report.files.iter().map(|file| file.size).sum::<u64>();
    let mut categories: Vec<_> = report.categories.iter().collect();
    categories.sort_by(|(_, a), (_, b)| b.bytes.cmp(&a.bytes));
    let rows = categories
        .into_iter()
        .map(|(name, summary)| CategoryRow {
            name: SharedString::from(name.as_str()),
            size: SharedString::from(format_size(summary.bytes)),
            files: SharedString::from(summary.files.to_string()),
            percent: SharedString::from(if total == 0 {
                "0.0%".to_string()
            } else {
                format!("{:.1}%", summary.bytes as f64 * 100.0 / total as f64)
            }),
            ratio: if total == 0 { 0.0 } else { summary.bytes as f32 / total as f32 },
            color: category_swatch(name),
        })
        .collect::<Vec<_>>();
    window.set_category_rows(ModelRc::from(std::rc::Rc::new(VecModel::from(rows))));

    let mut tree = TreeNode::directory(report.root.file_name().map_or_else(
        || report.root.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    ));
    for file in &report.files {
        let Ok(relative) = file.path.strip_prefix(&report.root) else {
            continue;
        };
        let components: Vec<_> = relative
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect();
        if components.is_empty() {
            continue;
        }
        let mut current = &mut tree;
        for (index, part) in components.iter().enumerate() {
            let last = index + 1 == components.len();
            current = current.children.entry(part.clone()).or_insert_with(|| {
                if last {
                    TreeNode::file(part.clone())
                } else {
                    TreeNode::directory(part.clone())
                }
            });
            current.bytes = current
                .bytes
                .saturating_add(if last { file.size } else { 0 });
            current.files = current.files.saturating_add(if last { 1 } else { 0 });
        }
        let mut parent = &mut tree;
        parent.bytes = parent.bytes.saturating_add(file.size);
        parent.files = parent.files.saturating_add(1);
        for part in components.iter().take(components.len().saturating_sub(1)) {
            parent = parent
                .children
                .get_mut(part)
                .expect("tree path was just inserted");
            parent.bytes = parent.bytes.saturating_add(file.size);
            parent.files = parent.files.saturating_add(1);
        }
    }
    TREE_CACHE.with(|cache| *cache.borrow_mut() = Some(tree));
    let mut rows = Vec::new();
    TREE_CACHE.with(|cache| if let Some(tree) = cache.borrow().as_ref() { flatten_tree(tree, 0, String::new(), &mut rows, &BTreeSet::new()); });
    window.set_tree_rows(ModelRc::from(std::rc::Rc::new(VecModel::from(rows))));
    window.set_tiles(ModelRc::from(std::rc::Rc::new(VecModel::from(
        make_treemap(&report.files),
    ))));
}

#[derive(Default, Clone)]
struct TreeNode {
    name: String,
    is_file: bool,
    bytes: u64,
    files: u64,
    children: BTreeMap<String, TreeNode>,
}

impl TreeNode {
    fn directory(name: String) -> Self {
        Self {
            name,
            ..Self::default()
        }
    }
    fn file(name: String) -> Self {
        Self {
            name,
            is_file: true,
            ..Self::default()
        }
    }
}

fn flatten_tree(node: &TreeNode, depth: usize, parent_key: String, rows: &mut Vec<TreeRow>, expanded: &BTreeSet<String>) {
    let key = if parent_key.is_empty() { node.name.clone() } else { format!("{parent_key}/{}", node.name) };
    rows.push(TreeRow {
        name: SharedString::from(node.name.as_str()),
        kind: SharedString::from(if node.is_file {
            "Файл"
        } else {
            "Папка"
        }),
        size: SharedString::from(format_size(node.bytes)),
        files: SharedString::from(node.files.to_string()),
        indent: (depth * 16) as f32,
        color: slint::Color::from_rgb_u8(if node.is_file { 126 } else { 122 }, if node.is_file { 153 } else { 133 }, if node.is_file { 177 } else { 106 }),
        is_file: node.is_file,
        expandable: !node.children.is_empty(),
        expanded: expanded.contains(&key) || depth == 0,
        key: key.clone().into(),
    });
    if depth > 0 && !expanded.contains(&key) { return; }
    let mut children: Vec<_> = node.children.values().collect();
    children.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.name.cmp(&b.name)));
    for child in children {
        flatten_tree(child, depth + 1, key.clone(), rows, expanded);
    }
}

fn category_swatch(name: &str) -> slint::Color {
    let colors = [
        (90,145,190), (81,157,126), (184,130,73), (151,111,190),
        (190,91,98),  (67,150,163), (177,157,70), (93,151,91),
        (163,105,148),(107,134,190),(191,119,66), (92,117,160),
        (149,161,91), (157,101,98), (88,130,210),  (110,110,120),
    ];
    let index = match name {
        "Видео" => 0, "Музыка" => 1, "Фото" => 2, "Документы" => 3,
        "Архивы" => 4, "Программы" => 5, "Игры" => 6, "Системные" => 7,
        "Скрипты" => 8, "Базы данных" => 9, "Веб-файлы" => 10,
        "Образы дисков" => 11, "Шрифты" => 12, "Логи" => 13,
        "Разработка" => 14, _ => 15,
    };
    let (r,g,b) = colors[index]; slint::Color::from_rgb_u8(r,g,b)
}

fn make_treemap(files: &[disk_analyzer::FileEntry]) -> Vec<Tile> {
    const MAX_TILES: usize = 240;
    const COLORS: [(u8, u8, u8); 16] = [
        (57, 83, 104), (63, 96, 87), (112, 82, 53), (83, 70, 112),
        (111, 63, 67), (49, 84, 101), (106, 91, 50), (67, 91, 62),
        (93, 67, 84), (58, 91, 91), (103, 76, 55), (70, 77, 105),
        (86, 93, 57), (101, 62, 91), (50, 95, 155), (90, 90, 100),
    ];
    let mut sorted: Vec<_> = files.iter().collect();
    sorted.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));
    let mut items: Vec<(String, u64, usize)> = sorted
        .iter()
        .take(MAX_TILES - 1)
        .map(|file| {
            (
                file.path.file_name().map_or_else(
                    || file.path.display().to_string(),
                    |n| n.to_string_lossy().into_owned(),
                ),
                file.size,
                category_color(&file.category),
            )
        })
        .collect();
    let other_size: u64 = sorted
        .iter()
        .skip(MAX_TILES - 1)
        .map(|file| file.size)
        .sum();
    if sorted.len() > MAX_TILES - 1 {
        items.push(("Остальные файлы".to_string(), other_size, COLORS.len() - 1));
    }
    if items.is_empty() {
        return Vec::new();
    }
    let mut result = Vec::with_capacity(items.len());
    let weights: Vec<u64> = items.iter().map(|(_, size, _)| (*size).max(1)).collect();
    let colors = COLORS;
    #[allow(clippy::too_many_arguments)]
    fn subdivide(
        items: &[(String, u64, usize)],
        weights: &[u64],
        start: usize,
        end: usize,
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        output: &mut Vec<Tile>,
        colors: &[(u8, u8, u8); 16],
    ) {
        if end <= start {
            return;
        }
        if end - start == 1 {
            let (label, size, color_index) = &items[start];
            let (r, g, b) = colors[*color_index % colors.len()];
            output.push(Tile {
                x,
                y,
                width: w,
                height: h,
                label: label.clone().into(),
                size: format_size(*size).into(),
                color: slint::Color::from_rgb_u8(r, g, b),
            });
            return;
        }
        let total: u64 = weights[start..end].iter().sum();
        let mut accumulated = 0u64;
        let mut middle = start + 1;
        for (index, weight) in weights.iter().enumerate().take(end - 1).skip(start) {
            accumulated = accumulated.saturating_add(*weight);
            middle = index + 1;
            if accumulated.saturating_mul(2) >= total {
                break;
            }
        }
        let ratio = weights[start..middle].iter().sum::<u64>() as f32 / total.max(1) as f32;
        if w >= h {
            let split = w * ratio;
            subdivide(
                items, weights, start, middle, x, y, split, h, output, colors,
            );
            subdivide(
                items,
                weights,
                middle,
                end,
                x + split,
                y,
                w - split,
                h,
                output,
                colors,
            );
        } else {
            let split = h * ratio;
            subdivide(
                items, weights, start, middle, x, y, w, split, output, colors,
            );
            subdivide(
                items,
                weights,
                middle,
                end,
                x,
                y + split,
                w,
                h - split,
                output,
                colors,
            );
        }
    }
    let len = items.len();
    subdivide(
        &items,
        &weights,
        0,
        len,
        0.0,
        0.0,
        1.0,
        1.0,
        &mut result,
        &colors,
    );
    result
}

fn category_color(category: &str) -> usize {
    match category {
        "Системные" => 0, "Программы" => 1, "Игры" => 2, "Видео" => 3,
        "Музыка" => 4, "Фото" => 5, "Документы" => 6, "Архивы" => 7,
        "Базы данных" => 8, "Скрипты" => 9, "Веб-файлы" => 10,
        "Образы дисков" => 11, "Шрифты" => 12, "Логи" => 13,
        "Разработка" => 14,
        _ => 15,
    }
}

fn format_duration(duration: Duration) -> String {
    if duration.as_secs_f64() < 60.0 {
        format!("{:.2} с", duration.as_secs_f64())
    } else {
        format!(
            "{} мин {:02} с",
            duration.as_secs() / 60,
            duration.as_secs() % 60
        )
    }
}

fn open_path(path: &std::path::Path) -> io::Result<()> {
    #[cfg(target_os = "windows")]
    let result = std::process::Command::new("explorer").arg(path).spawn();
    #[cfg(target_os = "macos")]
    let result = std::process::Command::new("open").arg(path).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let result = std::process::Command::new("xdg-open").arg(path).spawn();
    result.map(|_| ())
}

fn default_report_dir(root: &std::path::Path) -> PathBuf {
    let label = root
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("root");
    PathBuf::from(format!("Disk_{label}_Report"))
}

fn missing_value(argument: &str) -> io::Error {
    invalid_value(&format!("после {argument} требуется значение"))
}

fn invalid_value(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn print_help() {
    println!("Disk Analyzer — кроссплатформенный анализатор диска\n");
    println!("Использование: disk-analyzer [--root PATH] [--report-dir PATH] [--workers N]\n");
    println!("  -r, --root PATH       папка или точка монтирования (по умолчанию: текущая папка)");
    println!("      --report-dir PATH куда сохранить отчёт");
    println!("      --workers N        число рабочих потоков для чтения метаданных");
    println!("  -h, --help             показать эту справку");
}
