use std::env;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use disk_analyzer::{AnalyzeOptions, Analyzer, Progress, format_size, write_report};

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
