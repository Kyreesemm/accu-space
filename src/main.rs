use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use disk_analyzer::{
    AnalysisReport, AnalyzeOptions, Analyzer, Progress, format_size, write_report,
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
            if let Ok(report) = &result
                && let Err(error) = write_report(report, &report_dir)
            {
                let ui = weak.clone();
                let message = format!("Анализ готов, но отчёт не сохранён: {error}");
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(window) = ui.upgrade() {
                        window.set_status_text(message.into());
                    }
                });
                return;
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
            let root = PathBuf::from(window.get_root_path().to_string());
            let folder = default_report_dir(&root);
            if folder.exists() {
                if let Err(error) = open_path(&folder) {
                    window.set_status_text(format!("Не удалось открыть отчёт: {error}").into());
                }
            } else {
                window.set_status_text("Сначала выполните анализ: отчёт ещё не создан".into());
            }
        }
    });

    app.run()
        .map_err(|error| io::Error::other(error.to_string()))
}

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
        })
        .collect::<Vec<_>>();
    window.set_category_rows(ModelRc::from(std::rc::Rc::new(VecModel::from(rows))));
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
