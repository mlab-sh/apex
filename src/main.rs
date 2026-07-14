//! APEX CLI entry point — `apex scan path/to/apk`.

mod adb_checks;
mod analyzers;
mod cert_util;
mod device;
mod elf_util;
mod models;
mod output;
mod scanner;
mod stalkerware_iocs;
mod util;
mod xml;

use clap::{Parser, Subcommand, ValueEnum};
use output::json::export_json;
use output::terminal::{print_finding, print_header, print_summary};
use std::path::PathBuf;
use std::process::ExitCode;

const SEVERITY_ORDER: [&str; 5] = ["critical", "high", "medium", "low", "info"];

#[derive(Parser)]
#[command(
    name = "apex",
    version = "0.1.0",
    about = "APEX — Static analysis for APK/IPA (mlab.sh)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze an APK/IPA/AAB/XAPK file
    Scan(ScanArgs),
    /// Connect to an Android phone over USB (ADB) and scan its installed apps
    Device(DeviceArgs),
}

#[derive(clap::Args)]
struct DeviceArgs {
    #[command(subcommand)]
    action: DeviceAction,
}

#[derive(Subcommand)]
enum DeviceAction {
    /// Wait (poll) until an ADB USB device is connected, then exit
    Listen(DeviceListenArgs),
    /// List installed non-system (third-party) packages
    List(DeviceCommonArgs),
    /// Assess the device's own security posture (hardening, privacy, abuse vectors)
    Posture(DevicePostureArgs),
    /// Pull all non-system APKs + device info to a local directory
    Dump(DeviceDumpArgs),
    /// Pull and scan installed non-system apps
    Scan(DeviceScanArgs),
    /// Run a raw ADB shell command on the device (power-user / debugging)
    Shell(DeviceShellArgs),
}

#[derive(clap::Args)]
struct DevicePostureArgs {
    /// Path to a custom ADB private key (default: ~/.android/adbkey)
    #[arg(long = "adb-key")]
    adb_key: Option<PathBuf>,
    /// Emit the posture report as JSON
    #[arg(long = "json")]
    json_output: bool,
    /// JSON output file path
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
    /// Print the proof/evidence under each finding
    #[arg(long)]
    detail: bool,
    /// Exit with code 1 if any finding at this severity or above (for CI/CD)
    #[arg(long = "fail-on", value_enum)]
    fail_on: Option<FailLevel>,
}

#[derive(clap::Args)]
struct DeviceShellArgs {
    /// The shell command to run (e.g. "getprop ro.build.version.sdk")
    #[arg(required = true, num_args = 1..)]
    command: Vec<String>,
    /// Path to a custom ADB private key (default: ~/.android/adbkey)
    #[arg(long = "adb-key")]
    adb_key: Option<PathBuf>,
}

#[derive(clap::Args)]
struct DeviceDumpArgs {
    /// Dump only this package (default: every third-party app)
    #[arg(long)]
    package: Option<String>,
    /// Output directory (default: ./apex_dump)
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
    /// Path to a custom ADB private key (default: ~/.android/adbkey)
    #[arg(long = "adb-key")]
    adb_key: Option<PathBuf>,
}

#[derive(clap::Args)]
struct DeviceListenArgs {
    /// Seconds between USB polls
    #[arg(long, default_value_t = 1.0)]
    interval: f64,
    /// Give up after this many seconds (default: wait forever)
    #[arg(long)]
    timeout: Option<f64>,
}

#[derive(clap::Args)]
struct DeviceCommonArgs {
    /// Path to a custom ADB private key (default: ~/.android/adbkey)
    #[arg(long = "adb-key")]
    adb_key: Option<PathBuf>,
}

#[derive(clap::Args)]
struct DeviceScanArgs {
    /// Scan only this package (default: every third-party app)
    #[arg(long)]
    package: Option<String>,
    /// Path to a custom ADB private key (default: ~/.android/adbkey)
    #[arg(long = "adb-key")]
    adb_key: Option<PathBuf>,
    /// Write a JSON report per app
    #[arg(long = "json")]
    json_output: bool,
    /// Directory for JSON reports (default: current directory)
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
    /// Print the proof/evidence under each finding
    #[arg(long)]
    detail: bool,
    /// Skip on-device runtime enrichment (granted permissions, app-ops, installer)
    #[arg(long = "no-runtime")]
    no_runtime: bool,
    /// Exit with code 1 if any finding at this severity or above (for CI/CD)
    #[arg(long = "fail-on", value_enum)]
    fail_on: Option<FailLevel>,
}

#[derive(clap::Args)]
struct ScanArgs {
    /// File to analyze (.apk, .ipa, .aab, .xapk)
    file: PathBuf,
    /// Formatted terminal output (default)
    #[arg(long)]
    show: bool,
    /// JSON output
    #[arg(long = "json")]
    json_output: bool,
    /// JSON output file path
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
    /// Print the proof/evidence (description + metadata) under each finding
    #[arg(long)]
    detail: bool,
    /// Exit with code 1 if any finding at this severity or above (for CI/CD)
    #[arg(long = "fail-on", value_enum)]
    fail_on: Option<FailLevel>,
}

#[derive(Copy, Clone, ValueEnum)]
enum FailLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl FailLevel {
    fn as_str(self) -> &'static str {
        match self {
            FailLevel::Critical => "critical",
            FailLevel::High => "high",
            FailLevel::Medium => "medium",
            FailLevel::Low => "low",
            FailLevel::Info => "info",
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => run_scan(args),
        Command::Device(args) => match args.action {
            DeviceAction::Listen(a) => run_device_listen(a),
            DeviceAction::List(a) => run_device_list(a),
            DeviceAction::Posture(a) => run_device_posture(a),
            DeviceAction::Dump(a) => run_device_dump(a),
            DeviceAction::Scan(a) => run_device_scan(a),
            DeviceAction::Shell(a) => run_device_shell(a),
        },
    }
}

fn run_device_posture(args: DevicePostureArgs) -> ExitCode {
    use models::{security_score, severity_counts, Severity};
    use serde_json::{json, Value};

    let mut phone = match device::Phone::connect(args.adb_key) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            return ExitCode::from(1);
        }
    };

    let posture = match adb_checks::collect_posture(&mut phone) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            return ExitCode::from(1);
        }
    };

    // Sort most-severe first for display.
    let mut findings = posture.findings;
    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    if !args.json_output || args.detail {
        // Header.
        let label = posture
            .info
            .rows
            .iter()
            .find(|(k, _)| *k == "model")
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| "device".into());
        print_header(&format!("Device posture — {label}"), "device");

        // Device info block.
        println!("\x1b[1m\x1b[36mDevice\x1b[0m");
        for (k, v) in &posture.info.rows {
            if !v.is_empty() {
                println!("  \x1b[1m{k:<18}\x1b[0m {v}");
            }
        }
        println!();

        if findings.is_empty() {
            println!("  \x1b[32mNo posture issues detected.\x1b[0m\n");
        }
        for f in &findings {
            print_finding(f, args.detail);
        }

        // Summary + score (mirrors the package-scan summary).
        println!();
        println!("\x1b[1mSummary\x1b[0m");
        let counts = severity_counts(&findings);
        for sev in Severity::ALL {
            let n = counts.get(sev.value()).and_then(|v| v.as_u64()).unwrap_or(0);
            let label = sev.value().to_uppercase();
            if n > 0 {
                println!("  \x1b[{}m{:<10}\x1b[0m \x1b[{}m{:>6}\x1b[0m", sev.ansi(), label, sev.ansi(), n);
            } else {
                println!("  \x1b[2m{label:<10}\x1b[0m \x1b[2m{n:>6}\x1b[0m");
            }
        }
        let score = security_score(&findings);
        let color = if score >= 80 { "32" } else if score >= 50 { "33" } else { "31" };
        println!("\n\x1b[1mPosture Score:\x1b[0m \x1b[1m\x1b[{color}m{score}/100\x1b[0m");
        if posture.rooted {
            println!("\x1b[2mNote: root/verified-boot signals are property-based and best-effort (spoofable).\x1b[0m");
        }
        println!();
    }

    if args.json_output {
        let info: serde_json::Map<String, Value> = posture
            .info
            .rows
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(k, v)| ((*k).to_string(), json!(v)))
            .collect();
        let report = json!({
            "schema_version": 1,
            "kind": "device_posture",
            "device": info,
            "rooted": posture.rooted,
            "posture_score": security_score(&findings),
            "summary": severity_counts(&findings),
            "findings": findings.iter().map(|f| f.to_json()).collect::<Vec<_>>(),
        });
        let text = serde_json::to_string_pretty(&report).unwrap_or_default();
        if let Some(path) = &args.output {
            if let Err(e) = std::fs::write(path, &text) {
                eprintln!("\x1b[31mError writing JSON: {e}\x1b[0m");
                return ExitCode::from(1);
            }
            println!("\x1b[32mJSON report: {}\x1b[0m", path.display());
        } else if !args.detail {
            println!("{text}");
        }
    }

    // CI gate.
    if let Some(fail_on) = args.fail_on {
        let idx = SEVERITY_ORDER.iter().position(|&s| s == fail_on.as_str()).unwrap_or(0);
        let failing: std::collections::HashSet<&str> =
            SEVERITY_ORDER[..=idx].iter().copied().collect();
        if findings.iter().any(|f| failing.contains(f.severity.value())) {
            return ExitCode::from(1);
        }
    }

    ExitCode::SUCCESS
}

fn run_device_shell(args: DeviceShellArgs) -> ExitCode {
    let mut phone = match device::Phone::connect(args.adb_key) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            return ExitCode::from(1);
        }
    };
    let cmd = args.command.join(" ");
    match phone.run(&cmd) {
        Ok(out) => {
            print!("{out}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            ExitCode::from(1)
        }
    }
}

fn run_scan(mut args: ScanArgs) -> ExitCode {
    let file_path = args.file.clone();

    if !file_path.exists() {
        eprintln!(
            "\x1b[31mError: file not found — {}\x1b[0m",
            file_path.display()
        );
        return ExitCode::from(1);
    }

    if scanner::detect_app_type(&file_path).is_none() {
        eprintln!(
            "\x1b[31mError: unsupported format. Valid extensions: {}\x1b[0m",
            scanner::VALID_EXTENSIONS.join(", ")
        );
        return ExitCode::from(1);
    }

    // Default to --show if no output flag was given; --detail implies --show.
    if (!args.show && !args.json_output) || args.detail {
        args.show = true;
    }

    if args.show {
        let ext = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        print_header(&file_path.to_string_lossy(), ext);
    }

    let detail = args.detail;
    let result = if args.show {
        scanner::scan(&file_path, Some(|f: &models::Finding| print_finding(f, detail)))
    } else {
        scanner::scan::<fn(&models::Finding)>(&file_path, None)
    };

    if args.show {
        print_summary(&result);
    }

    if args.json_output {
        match export_json(&result, args.output.as_deref()) {
            Ok(out_path) => {
                if !args.show {
                    let data = result.to_json();
                    println!("{}", serde_json::to_string_pretty(&data).unwrap_or_default());
                }
                println!("\x1b[32mJSON report: {}\x1b[0m", out_path.display());
            }
            Err(e) => {
                eprintln!("\x1b[31mError writing JSON: {e}\x1b[0m");
                return ExitCode::from(1);
            }
        }
    }

    if fails_threshold(&result, args.fail_on) {
        return ExitCode::from(1);
    }

    ExitCode::SUCCESS
}

fn fails_threshold(result: &models::ScanResult, fail_on: Option<FailLevel>) -> bool {
    let fail_on = match fail_on {
        Some(f) => f,
        None => return false,
    };
    let threshold_idx = SEVERITY_ORDER
        .iter()
        .position(|&s| s == fail_on.as_str())
        .unwrap_or(0);
    let failing: std::collections::HashSet<&str> =
        SEVERITY_ORDER[..=threshold_idx].iter().copied().collect();
    result
        .findings
        .iter()
        .any(|f| failing.contains(f.severity.value()))
}

fn run_device_listen(args: DeviceListenArgs) -> ExitCode {
    use std::io::Write;
    use std::time::{Duration, Instant};

    let interval = Duration::from_secs_f64(args.interval.max(0.05));
    let start = Instant::now();
    let spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    let mut tick = 0usize;

    loop {
        match device::detect_devices() {
            Ok(devs) if !devs.is_empty() => {
                let ids: Vec<String> = devs
                    .iter()
                    .map(|(v, p)| format!("{v:04x}:{p:04x}"))
                    .collect();
                // Clear the spinner line.
                eprint!("\r\x1b[2K");
                let _ = std::io::stderr().flush();
                println!(
                    "\x1b[32m✓ Device connected\x1b[0m ({})",
                    ids.join(", ")
                );
                return ExitCode::SUCCESS;
            }
            Ok(_) => {}
            Err(e) => {
                eprint!("\r\x1b[2K");
                eprintln!("\x1b[33m{e}\x1b[0m");
            }
        }

        let elapsed = start.elapsed().as_secs_f64();
        if let Some(t) = args.timeout {
            if elapsed >= t {
                eprint!("\r\x1b[2K");
                let _ = std::io::stderr().flush();
                eprintln!("\x1b[31m✗ Timed out after {t:.0}s — no device.\x1b[0m");
                return ExitCode::from(1);
            }
        }

        eprint!(
            "\r\x1b[2K\x1b[36m{}\x1b[0m waiting for an ADB USB device… \x1b[2m({:.0}s)\x1b[0m",
            spinner[tick % spinner.len()],
            elapsed
        );
        let _ = std::io::stderr().flush();
        tick += 1;
        std::thread::sleep(interval);
    }
}

fn run_device_list(args: DeviceCommonArgs) -> ExitCode {
    let mut phone = match device::Phone::connect(args.adb_key) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            return ExitCode::from(1);
        }
    };
    let pkgs = match phone.list_third_party() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            return ExitCode::from(1);
        }
    };
    println!(
        "\x1b[1m\x1b[36m{}\x1b[0m third-party package(s):",
        pkgs.len()
    );
    for pkg in &pkgs {
        println!("  {pkg}");
    }
    ExitCode::SUCCESS
}

const DUMP_PROPS: &[(&str, &str)] = &[
    ("model", "ro.product.model"),
    ("manufacturer", "ro.product.manufacturer"),
    ("brand", "ro.product.brand"),
    ("device", "ro.product.device"),
    ("product", "ro.product.name"),
    ("android_release", "ro.build.version.release"),
    ("sdk", "ro.build.version.sdk"),
    ("security_patch", "ro.build.version.security_patch"),
    ("serial", "ro.serialno"),
    ("cpu_abi", "ro.product.cpu.abi"),
    ("build_fingerprint", "ro.build.fingerprint"),
];

fn run_device_dump(args: DeviceDumpArgs) -> ExitCode {
    use serde_json::{json, Map, Value};

    let mut phone = match device::Phone::connect(args.adb_key) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            return ExitCode::from(1);
        }
    };

    // Device info.
    let props = phone.props().unwrap_or_default();
    let mut device_info = Map::new();
    println!("\x1b[1m\x1b[36mDevice\x1b[0m");
    for (label, key) in DUMP_PROPS {
        if let Some(v) = props.get(*key) {
            if !v.is_empty() {
                println!("  \x1b[1m{label:<18}\x1b[0m {v}");
                device_info.insert((*label).to_string(), json!(v));
            }
        }
    }
    println!();

    let packages: Vec<String> = match &args.package {
        Some(p) => vec![p.clone()],
        None => match phone.list_third_party() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("\x1b[31m{e}\x1b[0m");
                return ExitCode::from(1);
            }
        },
    };

    let out_dir = args.output.unwrap_or_else(|| PathBuf::from("apex_dump"));
    if let Err(e) = std::fs::create_dir_all(&out_dir) {
        eprintln!("\x1b[31mcannot create {}: {e}\x1b[0m", out_dir.display());
        return ExitCode::from(1);
    }

    println!(
        "\x1b[1m\x1b[36mDumping {} app(s) to {}…\x1b[0m",
        packages.len(),
        out_dir.display()
    );

    let mut apps: Vec<Value> = Vec::new();
    let mut ok = 0usize;
    for (i, pkg) in packages.iter().enumerate() {
        let remote = match phone.base_apk_path(pkg) {
            Ok(Some(r)) => r,
            Ok(None) => {
                eprintln!("\x1b[33m[skip] {pkg}: no APK path\x1b[0m");
                continue;
            }
            Err(e) => {
                eprintln!("\x1b[33m[skip] {pkg}: {e}\x1b[0m");
                continue;
            }
        };
        let local = out_dir.join(format!("{pkg}.apk"));
        if let Err(e) = phone.pull(&remote, &local) {
            eprintln!("\x1b[33m[skip] {pkg}: {e}\x1b[0m");
            continue;
        }
        let size = std::fs::metadata(&local).map(|m| m.len()).unwrap_or(0);
        let sha256 = scanner::compute_hash(&local).unwrap_or_default();
        ok += 1;
        println!(
            "  \x1b[32m[{:>3}/{}]\x1b[0m {pkg}  \x1b[2m({} KB)\x1b[0m",
            i + 1,
            packages.len(),
            size / 1024
        );
        apps.push(json!({
            "package": pkg,
            "remote_path": remote,
            "file": format!("{pkg}.apk"),
            "size_bytes": size,
            "sha256": sha256,
        }));
    }

    // Write the manifest.
    let manifest = json!({
        "device": Value::Object(device_info),
        "app_count": ok,
        "apps": apps,
    });
    let manifest_path = out_dir.join("manifest.json");
    match serde_json::to_string_pretty(&manifest) {
        Ok(s) => {
            if let Err(e) = std::fs::write(&manifest_path, s) {
                eprintln!("\x1b[31mError writing manifest: {e}\x1b[0m");
            } else {
                println!(
                    "\n\x1b[32m✓ Dumped {ok}/{} app(s) → {}\x1b[0m",
                    packages.len(),
                    out_dir.display()
                );
                println!("\x1b[2mManifest: {}\x1b[0m", manifest_path.display());
            }
        }
        Err(e) => eprintln!("\x1b[31mError serializing manifest: {e}\x1b[0m"),
    }

    ExitCode::SUCCESS
}

fn run_device_scan(args: DeviceScanArgs) -> ExitCode {
    let mut phone = match device::Phone::connect(args.adb_key) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            return ExitCode::from(1);
        }
    };

    let packages: Vec<String> = match &args.package {
        Some(p) => vec![p.clone()],
        None => match phone.list_third_party() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("\x1b[31m{e}\x1b[0m");
                return ExitCode::from(1);
            }
        },
    };

    if packages.is_empty() {
        println!("No third-party packages found on the device.");
        return ExitCode::SUCCESS;
    }

    let tmp = match tempfile::Builder::new().prefix("apex_dev_").tempdir() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("\x1b[31mcannot create temp dir: {e}\x1b[0m");
            return ExitCode::from(1);
        }
    };

    println!(
        "\x1b[1m\x1b[36mScanning {} app(s) from device…\x1b[0m\n",
        packages.len()
    );

    let detail = args.detail;
    let mut any_fail = false;
    let mut ok = 0usize;

    for pkg in &packages {
        let remote = match phone.base_apk_path(pkg) {
            Ok(Some(r)) => r,
            Ok(None) => {
                eprintln!("\x1b[33m[skip] {pkg}: no APK path\x1b[0m");
                continue;
            }
            Err(e) => {
                eprintln!("\x1b[33m[skip] {pkg}: {e}\x1b[0m");
                continue;
            }
        };

        let local = tmp.path().join(format!("{pkg}.apk"));
        if let Err(e) = phone.pull(&remote, &local) {
            eprintln!("\x1b[33m[skip] {pkg}: {e}\x1b[0m");
            continue;
        }

        print_header(&format!("{pkg}  ({remote})"), "apk");
        let mut result = scanner::scan::<fn(&models::Finding)>(&local, None);
        if !args.no_runtime {
            let rt = adb_checks::runtime_findings(&mut phone, pkg);
            result.findings.extend(rt);
        }
        for f in &result.findings {
            print_finding(f, detail);
        }
        print_summary(&result);
        ok += 1;

        if args.json_output {
            let dir = args.output.clone().unwrap_or_else(|| PathBuf::from("."));
            let out_path = dir.join(format!("{pkg}_report.json"));
            match export_json(&result, Some(&out_path)) {
                Ok(p) => println!("\x1b[32mJSON report: {}\x1b[0m", p.display()),
                Err(e) => eprintln!("\x1b[31mError writing JSON for {pkg}: {e}\x1b[0m"),
            }
        }

        if fails_threshold(&result, args.fail_on) {
            any_fail = true;
        }
    }

    println!("\x1b[1mScanned {ok}/{} app(s).\x1b[0m", packages.len());

    if any_fail {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}
