//! APEX CLI entry point — `apex scan path/to/apk`.

mod adb_checks;
mod abx;
mod analyzers;
mod artifacts;
mod case;
mod comms;
mod cert_util;
mod device;
mod diff;
mod elf_util;
mod evidence;
mod history;
mod import;
mod ioc;
mod media;
mod models;
mod output;
mod report;
mod scanner;
mod sqlite_carve;
mod seizure;
mod stalkerware_iocs;
mod util;
mod verify;
mod xml;

use clap::{Parser, Subcommand, ValueEnum};
use output::json::export_json;
use output::terminal::{print_finding, print_header, print_summary};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const SEVERITY_ORDER: [&str; 5] = ["critical", "high", "medium", "low", "info"];

#[derive(Parser)]
#[command(
    name = "apex",
    version,
    about = "APEX — Android app analysis and phone investigation (mlab.sh)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze an APK/IPA/AAB/XAPK file
    Scan(ScanArgs),
    /// Analyze an existing extraction offline (a directory of APKs, no device)
    Analyze(AnalyzeArgs),
    /// Verify the integrity of a forensic evidence bundle (recompute hashes)
    Verify(VerifyArgs),
    /// Connect to an Android phone over USB (ADB) and scan its installed apps
    Device(DeviceArgs),
    /// Build a unified timeline (CSV or JSONL) from a `device acquire` case
    Timeline(TimelineArgs),
    /// Compare two `device acquire` cases of the same phone (what changed)
    Diff(DiffArgs),
    /// Write a self-contained HTML case report from a `device acquire` case
    Report(ReportArgs),
    /// Identifiers for legal requests (IMEI, IMSI, ICCID, line, MACs, accounts)
    Identifiers(IdentifiersArgs),
    /// Turn a full file-system extraction (dir, .zip, .tar, .tar.gz) into an APEX case
    Import(ImportArgs),
    /// Export communications collected under mandate (CSV + JSON)
    Comms(CommsArgs),
    /// Inventory shared-storage media: hashes, EXIF / GPS, hash sets, KML
    Media(MediaArgs),
}

#[derive(clap::Args)]
struct CommsArgs {
    /// Case directory (acquired or imported with --mandate)
    case: PathBuf,
    /// Output directory (default: <case>_comms)
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
}

#[derive(clap::Args)]
struct MediaArgs {
    /// Case directory (acquired or imported with --storage)
    case: PathBuf,
    /// Known-file hash set to set aside (repeatable), e.g. NSRL
    #[arg(long = "known")]
    known: Vec<PathBuf>,
    /// Alert hash set (repeatable): Project VIC / CAID VICS JSON, or one hash per line
    #[arg(long = "hashes")]
    hashes: Vec<PathBuf>,
    /// Output directory (default: <case>_media)
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
}

#[derive(clap::Args)]
struct ImportArgs {
    /// Extraction: directory, .zip, .tar or .tar.gz containing data/system/…
    source: PathBuf,
    /// Legal mandate reference: also copy communication databases (SMS / MMS,
    /// calls, contacts, WhatsApp, Telegram, Chrome). Recorded in the manifest.
    #[arg(long)]
    mandate: Option<String>,
    /// Also copy shared storage (data/media/0: photos, videos, downloads)
    #[arg(long)]
    storage: bool,
    /// Case directory to create
    #[arg(short = 'o', long = "output")]
    output: PathBuf,
    #[command(flatten)]
    case: CaseMetaArgs,
}

#[derive(clap::Args)]
struct IdentifiersArgs {
    /// Case directory written by `apex device acquire` (or `apex import`)
    case: PathBuf,
    /// Emit JSON (to -o, or stdout)
    #[arg(long = "json")]
    json_output: bool,
    /// JSON output file
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
}

#[derive(clap::Args)]
struct DiffArgs {
    /// Earlier case directory
    old: PathBuf,
    /// Later case directory
    new: PathBuf,
    /// STIX2 indicator bundle to match in both cases (repeatable)
    #[arg(long = "iocs")]
    iocs: Vec<PathBuf>,
    /// Emit the diff as JSON (to -o, or stdout)
    #[arg(long = "json")]
    json_output: bool,
    /// JSON output file
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
}

#[derive(clap::Args)]
struct ReportArgs {
    /// Case directory written by `apex device acquire`
    case: PathBuf,
    /// STIX2 indicator bundle to match (repeatable)
    #[arg(long = "iocs")]
    iocs: Vec<PathBuf>,
    /// Alert hash set (repeatable): Project VIC / CAID VICS JSON, NSRL, or one hash per line
    #[arg(long = "hashes")]
    hashes: Vec<PathBuf>,
    /// Output file (default: <case>/report.html)
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
}

#[derive(clap::Args)]
struct TimelineArgs {
    /// Case directory written by `apex device acquire`
    case: PathBuf,
    /// Output file: `.csv` (Timesketch columns) or `.jsonl` (default: <case>/timeline.csv)
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
}

#[derive(clap::Args)]
struct VerifyArgs {
    /// Evidence bundle directory (or path to its manifest.json)
    path: PathBuf,
}

#[derive(clap::Args)]
struct AnalyzeArgs {
    #[command(flatten)]
    case: CaseMetaArgs,
    /// Extraction directory to analyze (recursively) — or a single package file
    path: PathBuf,
    /// Also match this newline-separated list of installed package names against
    /// the stalkerware indicators (e.g. an extraction's installed-apps list)
    #[arg(long = "packages")]
    packages: Option<PathBuf>,
    /// STIX2 indicator bundle to match (repeatable), e.g. Echap's
    /// generated/stalkerware.stix2 or an MVT/Amnesty IOC file
    #[arg(long = "iocs")]
    iocs: Vec<PathBuf>,
    /// Alert hash set (repeatable): Project VIC / CAID VICS JSON, NSRL, or one hash per line
    #[arg(long = "hashes")]
    hashes: Vec<PathBuf>,
    /// Write a JSON report per package
    #[arg(long = "json")]
    json_output: bool,
    /// Directory for JSON reports (default: current directory)
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
    /// Print the proof/evidence under each finding
    #[arg(long)]
    detail: bool,
    /// Write a forensic evidence bundle (hashed inputs + manifest) to this dir
    #[arg(long = "evidence")]
    evidence: Option<PathBuf>,
    /// Exit with code 1 if any finding at this severity or above (for CI/CD)
    #[arg(long = "fail-on", value_enum)]
    fail_on: Option<FailLevel>,
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
    /// Forensic acquisition: APK splits + device metadata/logs + evidence bundle
    Acquire(DeviceAcquireArgs),
    /// Pull and scan installed non-system apps
    Scan(DeviceScanArgs),
    /// Run a raw ADB shell command on the device (power-user / debugging)
    Shell(DeviceShellArgs),
}

#[derive(clap::Args)]
struct DevicePostureArgs {
    #[command(flatten)]
    case: CaseMetaArgs,
    #[command(flatten)]
    conn: ConnArgs,
    /// Emit the posture report as JSON
    #[arg(long = "json")]
    json_output: bool,
    /// JSON output file path
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
    /// Print the proof/evidence under each finding
    #[arg(long)]
    detail: bool,
    /// Write a forensic evidence bundle (audit log + hashed manifest) to this dir
    #[arg(long = "evidence")]
    evidence: Option<PathBuf>,
    /// Exit with code 1 if any finding at this severity or above (for CI/CD)
    #[arg(long = "fail-on", value_enum)]
    fail_on: Option<FailLevel>,
}

/// How to reach the phone (shared by every `device` subcommand).
#[derive(clap::Args, Clone)]
struct ConnArgs {
    /// Path to a custom ADB private key (default: ~/.android/adbkey)
    #[arg(long = "adb-key")]
    adb_key: Option<PathBuf>,
    /// USB serial of the phone to use when several are plugged in
    #[arg(long, conflicts_with = "tcp")]
    serial: Option<String>,
    /// Connect over the network instead of USB: HOST[:PORT] (after `adb tcpip 5555`)
    #[arg(long)]
    tcp: Option<String>,
}

impl ConnArgs {
    fn connect(&self) -> Result<device::Phone, String> {
        device::Phone::connect(self.adb_key.clone(), self.serial.as_deref(), self.tcp.as_deref())
    }
}

/// Case / examiner metadata recorded in the evidence manifest and the report.
#[derive(clap::Args, Clone, Default)]
struct CaseMetaArgs {
    /// Case or exhibit reference (e.g. "2026-0142 / exhibit 3")
    #[arg(long = "case-id")]
    case_id: Option<String>,
    /// Name of the examiner running APEX
    #[arg(long)]
    examiner: Option<String>,
    /// Free-text note (legal basis, context, chain of custody)
    #[arg(long = "case-notes")]
    case_notes: Option<String>,
}

impl CaseMetaArgs {
    fn to_json(&self) -> serde_json::Value {
        let mut m = serde_json::Map::new();
        for (k, v) in [("case_id", &self.case_id), ("examiner", &self.examiner), ("notes", &self.case_notes)] {
            if let Some(v) = v {
                m.insert(k.into(), serde_json::json!(v));
            }
        }
        serde_json::Value::Object(m)
    }
}

#[derive(clap::Args)]
struct DeviceShellArgs {
    /// The shell command to run (e.g. "getprop ro.build.version.sdk")
    #[arg(required = true, num_args = 1..)]
    command: Vec<String>,
    #[command(flatten)]
    conn: ConnArgs,
}

#[derive(clap::Args)]
struct DeviceDumpArgs {
    /// Dump only this package (default: every third-party app)
    #[arg(long)]
    package: Option<String>,
    /// Output directory (default: ./apex_dump)
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
    #[command(flatten)]
    conn: ConnArgs,
}

#[derive(clap::Args)]
struct DeviceAcquireArgs {
    #[command(flatten)]
    case: CaseMetaArgs,
    /// Output directory (default: ./apex_acquire)
    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,
    /// Acquire only this package (default: every third-party app)
    #[arg(long)]
    package: Option<String>,
    /// Skip the (large) logcat capture
    #[arg(long = "no-logcat")]
    no_logcat: bool,
    /// Skip the (large) usage-stats capture
    #[arg(long = "no-usagestats")]
    no_usagestats: bool,
    /// Skip the full bugreport (slow: 1-5 min, 10-100 MB)
    #[arg(long = "no-bugreport")]
    no_bugreport: bool,
    /// Skip the screenshot of the current screen
    #[arg(long = "no-screenshot")]
    no_screenshot: bool,
    /// Capture notification *content* (titles, message previews) instead of the
    /// redacted dump. Message content is legally sensitive: only with a mandate.
    #[arg(long = "notification-content")]
    notification_content: bool,
    /// Triage: volatile state, remote-wipe check and identifiers only (< 1 min)
    #[arg(long)]
    triage: bool,
    /// Legal mandate reference: also collect SMS, MMS (+ attachments), call log
    /// and contacts. Recorded in the manifest.
    #[arg(long)]
    mandate: Option<String>,
    /// Pull shared storage (photos, videos, downloads, messaging media)
    #[arg(long)]
    storage: bool,
    #[command(flatten)]
    conn: ConnArgs,
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
    #[command(flatten)]
    conn: ConnArgs,
}

#[derive(clap::Args)]
struct DeviceScanArgs {
    #[command(flatten)]
    case: CaseMetaArgs,
    /// Scan only this package (default: every third-party app)
    #[arg(long)]
    package: Option<String>,
    #[command(flatten)]
    conn: ConnArgs,
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
    /// Write a forensic evidence bundle (audit log + hashed manifest) to this dir
    #[arg(long = "evidence")]
    evidence: Option<PathBuf>,
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
        Command::Analyze(args) => run_analyze(args),
        Command::Verify(args) => run_verify(args),
        Command::Timeline(args) => run_timeline(args),
        Command::Diff(args) => run_diff(args),
        Command::Report(args) => run_report(args),
        Command::Identifiers(args) => run_identifiers(args),
        Command::Import(args) => run_import(args),
        Command::Comms(args) => run_comms(args),
        Command::Media(args) => run_media(args),
        Command::Device(args) => match args.action {
            DeviceAction::Listen(a) => run_device_listen(a),
            DeviceAction::List(a) => run_device_list(a),
            DeviceAction::Posture(a) => run_device_posture(a),
            DeviceAction::Dump(a) => run_device_dump(a),
            DeviceAction::Acquire(a) => run_device_acquire(a),
            DeviceAction::Scan(a) => run_device_scan(a),
            DeviceAction::Shell(a) => run_device_shell(a),
        },
    }
}

fn run_device_posture(args: DevicePostureArgs) -> ExitCode {
    use models::{security_score, severity_counts, Severity};
    use serde_json::{json, Value};

    let mut phone = match args.conn.connect() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            return ExitCode::from(1);
        }
    };
    live_wipe_alert(&mut phone);

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
        "device": info.clone(),
        "rooted": posture.rooted,
        "posture_score": security_score(&findings),
        "summary": severity_counts(&findings),
        "findings": findings.iter().map(|f| f.to_json()).collect::<Vec<_>>(),
    });
    let report_text = serde_json::to_string_pretty(&report).unwrap_or_default();

    if args.json_output {
        if let Some(path) = &args.output {
            if let Err(e) = std::fs::write(path, &report_text) {
                eprintln!("\x1b[31mError writing JSON: {e}\x1b[0m");
                return ExitCode::from(1);
            }
            println!("\x1b[32mJSON report: {}\x1b[0m", path.display());
        } else if !args.detail {
            println!("{report_text}");
        }
    }

    // Forensic evidence bundle: report + audit log + hashed manifest.
    if let Some(dir) = &args.evidence {
        let report_path = dir.join("posture_report.json");
        if let Err(e) = std::fs::create_dir_all(dir).and_then(|_| std::fs::write(&report_path, &report_text)) {
            eprintln!("\x1b[31mError writing evidence report: {e}\x1b[0m");
            return ExitCode::from(1);
        }
        match evidence::write_evidence(
            dir,
            &phone,
            "device_posture",
            Value::Object(info),
            &[report_path],
            Vec::new(),
            args.case.to_json(),
        ) {
            Ok((mpath, sha)) => {
                println!("\x1b[32m✓ Evidence bundle: {}\x1b[0m", dir.display());
                println!("\x1b[2m  manifest: {}  (sha256 {})\x1b[0m", mpath.display(), &sha[..16]);
            }
            Err(e) => {
                eprintln!("\x1b[31mError writing evidence bundle: {e}\x1b[0m");
                return ExitCode::from(1);
            }
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

/// Run a shell command, save its stdout to `path`, and record the file as a
/// hashed collected-artifact for the evidence manifest.
/// Remote-wipe check right after connecting, before anything slow.
fn live_wipe_alert(phone: &mut device::Phone) {
    let mut run = |c: &str| phone.run(c).unwrap_or_default();
    let (acc, dp, conn, pk, air) = (
        run("dumpsys account"),
        run("dumpsys device_policy"),
        run("dumpsys connectivity"),
        run("pm list packages"),
        run("settings get global airplane_mode_on"),
    );
    let pkgs = case::parse_packages(&pk).into_iter().map(|p| p.name).collect();
    let (why, online) = seizure::wipe_risks(&acc, &pkgs, &dp, &conn, Some(air.trim() == "1"));
    if let Some(b) = seizure::wipe_banner(&why, online) {
        eprint!("{b}");
    }
}

fn acquire_save(
    phone: &mut device::Phone,
    cmd: &str,
    path: &Path,
    out_root: &Path,
    collected: &mut Vec<serde_json::Value>,
) {
    use serde_json::json;
    match phone.run(cmd) {
        Ok(text) => {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::write(path, text.as_bytes()) {
                eprintln!("\x1b[33m[warn] cannot write {}: {e}\x1b[0m", path.display());
                return;
            }
            let sha = scanner::compute_hash(path).unwrap_or_default();
            let bytes = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            let rel = path.strip_prefix(out_root).unwrap_or(path).to_string_lossy().into_owned();
            collected.push(json!({
                "file": rel,
                "sha256": sha,
                "bytes": bytes,
                "source_cmd": cmd,
            }));
        }
        Err(e) => eprintln!("\x1b[33m[warn] '{cmd}': {e}\x1b[0m"),
    }
}

fn run_device_acquire(args: DeviceAcquireArgs) -> ExitCode {
    use serde_json::json;

    let mut phone = match args.conn.connect() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            return ExitCode::from(1);
        }
    };

    let out = args.output.unwrap_or_else(|| PathBuf::from("apex_acquire"));
    let device_dir = out.join("device");
    let apps_dir = out.join("apps");
    for d in [&out, &device_dir, &apps_dir] {
        if let Err(e) = std::fs::create_dir_all(d) {
            eprintln!("\x1b[31mcannot create {}: {e}\x1b[0m", d.display());
            return ExitCode::from(1);
        }
    }

    println!("\x1b[1m\x1b[36mForensic acquisition → {}\x1b[0m", out.display());
    let mut collected: Vec<serde_json::Value> = Vec::new();

    // ---- Device-level metadata & logs (non-root, read-only). ----
    println!("\x1b[2m  device metadata…\x1b[0m");
    // First, so the device clock is read right next to the host timestamp in the audit log.
    acquire_save(&mut phone, "date '+%Y-%m-%dT%H:%M:%S%z'", &device_dir.join("clock.txt"), &out, &mut collected);
    // Can the phone be wiped remotely? Say so before anything slow.
    acquire_save(&mut phone, "dumpsys account", &device_dir.join("accounts.txt"), &out, &mut collected);
    acquire_save(&mut phone, "dumpsys device_policy", &device_dir.join("device_policy.txt"), &out, &mut collected);
    acquire_save(&mut phone, "dumpsys connectivity", &device_dir.join("connectivity.txt"), &out, &mut collected);
    acquire_save(&mut phone, "pm list packages -f -i -u", &device_dir.join("packages.txt"), &out, &mut collected);
    {
        let rd = |f: &str| std::fs::read_to_string(device_dir.join(f)).unwrap_or_default();
        let pkgs = case::parse_packages(&rd("packages.txt")).into_iter().map(|p| p.name).collect();
        let (why, online) = seizure::wipe_risks(&rd("accounts.txt"), &pkgs, &rd("device_policy.txt"), &rd("connectivity.txt"), None);
        if let Some(b) = seizure::wipe_banner(&why, online) {
            eprint!("{b}");
        }
    }
    // Volatile state next, before our own activity adds processes, sockets or files.
    acquire_save(&mut phone, "ps -A -o USER,PID,PPID,NAME,ARGS", &device_dir.join("processes.txt"), &out, &mut collected);
    acquire_save(&mut phone, "ls -l /proc/[0-9]*/exe 2>/dev/null", &device_dir.join("proc_exe.txt"), &out, &mut collected);
    acquire_save(&mut phone, "cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6", &device_dir.join("net_sockets.txt"), &out, &mut collected);
    acquire_save(&mut phone, "ls -laR /data/local/tmp", &device_dir.join("local_tmp.txt"), &out, &mut collected);
    if !args.no_screenshot {
        // Written to the shell's scratch dir, pulled (hashed in the audit log), then removed.
        let remote = "/data/local/tmp/apex_screen.png";
        if phone.run(&format!("screencap -p {remote}")).is_ok() {
            if let Err(e) = phone.pull(remote, &device_dir.join("screen.png")) {
                eprintln!("\x1b[33m[warn] screenshot: {e}\x1b[0m");
            }
            let _ = phone.run(&format!("rm -f {remote}"));
        }
    }
    acquire_save(&mut phone, "getprop", &device_dir.join("getprop.txt"), &out, &mut collected);
    acquire_save(&mut phone, "pm list packages -3", &device_dir.join("packages_3.txt"), &out, &mut collected);
    acquire_save(&mut phone, "pm list packages -s -u", &device_dir.join("packages_system.txt"), &out, &mut collected);
    acquire_save(&mut phone, "pm list packages -U", &device_dir.join("packages_uid.txt"), &out, &mut collected);
    // Other users / work profile / clone space: their apps are not in the lists above.
    acquire_save(&mut phone, "pm list users", &device_dir.join("users.txt"), &out, &mut collected);
    let users = std::fs::read_to_string(device_dir.join("users.txt")).map(|t| history::parse_users(&t)).unwrap_or_default();
    let mut profile_only: Vec<(String, u32)> = Vec::new();
    for u in users.iter().filter(|u| u.id != 0) {
        let file = device_dir.join(format!("packages_3_user{}.txt", u.id));
        acquire_save(&mut phone, &format!("pm list packages -3 --user {}", u.id), &file, &out, &mut collected);
        let main: std::collections::HashSet<String> = std::fs::read_to_string(device_dir.join("packages_3.txt")).map(|t| case::parse_packages(&t).into_iter().map(|p| p.name).collect()).unwrap_or_default();
        for p in std::fs::read_to_string(&file).map(|t| case::parse_packages(&t)).unwrap_or_default() {
            if !main.contains(&p.name) && !profile_only.iter().any(|(n, _)| *n == p.name) {
                profile_only.push((p.name, u.id));
            }
        }
    }
    // Telephony identifiers for legal requests (IMEI, IMSI, ICCID, line number):
    // read-only getters of `iphonesubinfo`, numbered differently per Android
    // version, so call the first ones with both signatures and classify host-side.
    acquire_save(
        &mut phone,
        "for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do for a in 's16 com.android.shell' 'i32 0 s16 com.android.shell s16 null' 'i32 1 s16 com.android.shell s16 null'; do echo \"## $i $a\"; service call iphonesubinfo $i $a; done; done",
        &device_dir.join("iphonesubinfo.txt"),
        &out,
        &mut collected,
    );
    for ns in ["secure", "global", "system"] {
        acquire_save(&mut phone, &format!("settings list {ns}"), &device_dir.join(format!("settings_{ns}.txt")), &out, &mut collected);
    }

    if !args.triage {
    acquire_save(&mut phone, "dumpsys wifi", &device_dir.join("wifi.txt"), &out, &mut collected);
    acquire_save(&mut phone, "dumpsys bluetooth_manager", &device_dir.join("bluetooth.txt"), &out, &mut collected);
    // Investigation inputs: permission use history, hidden apps, enabled services.
    acquire_save(&mut phone, "dumpsys appops", &device_dir.join("appops.txt"), &out, &mut collected);
    acquire_save(
        &mut phone,
        "cmd package query-activities -a android.intent.action.MAIN -c android.intent.category.LAUNCHER",
        &device_dir.join("launcher_activities.txt"),
        &out,
        &mut collected,
    );

    println!("\x1b[2m  services, roles, network, sensors, storage…\x1b[0m");
    let notif_cmd = if args.notification_content { "dumpsys notification --noredact" } else { "dumpsys notification" };
    for (cmd, file) in [
        ("dumpsys activity services", "activity_services.txt"),
        ("dumpsys activity recents", "activity_recents.txt"),
        ("dumpsys activity broadcasts", "activity_broadcasts.txt"),
        ("dumpsys dbinfo", "dbinfo.txt"),
        ("dumpsys netstats --full --uid", "netstats.txt"),
        ("dumpsys package messages", "package_messages.txt"),
        (notif_cmd, "notification.txt"),
        ("dumpsys jobscheduler", "jobscheduler.txt"),
        ("dumpsys alarm", "alarm.txt"),
        ("dumpsys role", "role.txt"),
        ("dumpsys input_method", "input_method.txt"),
        ("dumpsys vpn_management", "vpn_management.txt"),
        ("dumpsys media.camera", "camera.txt"),
        ("dumpsys media.audio_flinger", "audio.txt"),
        ("dumpsys location", "location.txt"),
        ("cmd wifi list-networks", "wifi_networks.txt"),
        ("ls -laR /storage/emulated/0/", "sdcard_listing.txt"),
    ] {
        acquire_save(&mut phone, cmd, &device_dir.join(file), &out, &mut collected);
    }
    if let Some(m) = &args.mandate {
        println!("\x1b[2m  communications under mandate {m}…\x1b[0m");
        for (file, cmd) in comms::live_commands() {
            acquire_save(&mut phone, &cmd, &out.join("comms").join(file), &out, &mut collected);
        }
        let parts = std::fs::read_to_string(out.join("comms/mms_part.txt")).unwrap_or_default();
        for (id, name) in comms::attachment_parts(&parts) {
            if let Ok(b) = phone.run_raw(&format!("content read --uri content://mms/part/{id}")) {
                let p = out.join("comms/mms_parts").join(format!("{id}_{name}"));
                let _ = std::fs::create_dir_all(p.parent().unwrap());
                if std::fs::write(&p, &b).is_ok() {
                    collected.push(json!({"file": p.strip_prefix(&out).unwrap_or(&p).to_string_lossy(), "sha256": scanner::compute_hash(&p).unwrap_or_default(), "bytes": b.len(), "source_cmd": format!("content read --uri content://mms/part/{id}")}));
                }
            }
        }
    }
    if args.storage {
        let (ok, total, failed) = media::pull_storage(&mut phone, &out);
        println!("\x1b[2m  {ok} file(s) pulled ({:.1} MB){}\x1b[0m", total as f64 / 1_048_576.0, if failed > 0 { format!(", {failed} failed") } else { String::new() });
    }
    if !args.no_usagestats {
        println!("\x1b[2m  usage stats…\x1b[0m");
        acquire_save(&mut phone, "dumpsys usagestats", &device_dir.join("usagestats.txt"), &out, &mut collected);
    }
    if !args.no_logcat {
        println!("\x1b[2m  logcat…\x1b[0m");
        acquire_save(&mut phone, "logcat -d -v threadtime", &device_dir.join("logcat.txt"), &out, &mut collected);
    }

    if !args.no_bugreport {
        println!("\x1b[2m  bugreport (1-5 min, keep the phone unlocked and plugged in)…\x1b[0m");
        // The pull is recorded (and hashed) in the audit trail → manifest artifacts.
        if let Err(e) = phone.bugreport(&device_dir.join("bugreport.zip")) {
            eprintln!("\x1b[33m[warn] bugreport: {e}\x1b[0m");
        }
    }
    }

    // Device identifiers (best-effort; some are restricted on non-root shells).
    let props = phone.props().unwrap_or_default();
    let prop = |k: &str| props.get(k).cloned().unwrap_or_default();
    let android_id = phone.run("settings get secure android_id").map(|s| s.trim().to_string()).unwrap_or_default();
    let identifiers = json!({
        "model": prop("ro.product.model"),
        "manufacturer": prop("ro.product.manufacturer"),
        "serial": prop("ro.serialno"),
        "android_id": android_id,
        "android_release": prop("ro.build.version.release"),
        "sdk": prop("ro.build.version.sdk"),
        "security_patch": prop("ro.build.version.security_patch"),
        "build_fingerprint": prop("ro.build.fingerprint"),
        "cpu_abi": prop("ro.product.cpu.abi"),
    });
    let id_path = device_dir.join("identifiers.json");
    if std::fs::write(&id_path, serde_json::to_string_pretty(&identifiers).unwrap_or_default()).is_ok() {
        let sha = scanner::compute_hash(&id_path).unwrap_or_default();
        let bytes = std::fs::metadata(&id_path).map(|m| m.len()).unwrap_or(0);
        collected.push(json!({"file": "device/identifiers.json", "sha256": sha, "bytes": bytes, "source_cmd": "getprop + settings android_id"}));
    }

    // ---- Per-app acquisition: ALL APK splits + full dumpsys package. ----
    let packages: Vec<String> = match &args.package {
        _ if args.triage => Vec::new(),
        Some(p) => vec![p.clone()],
        None => match phone.list_third_party() {
            Ok(mut p) => {
                p.extend(profile_only.iter().map(|(n, _)| n.clone()));
                p
            }
            Err(e) => {
                eprintln!("\x1b[31m{e}\x1b[0m");
                return ExitCode::from(1);
            }
        },
    };
    if !args.triage {
        println!("\x1b[2m  {} app(s): APK splits + dumpsys…\x1b[0m", packages.len());
    }
    let mut apk_count = 0usize;
    for (i, pkg) in packages.iter().enumerate() {
        let appdir = apps_dir.join(pkg);
        if let Err(e) = std::fs::create_dir_all(&appdir) {
            eprintln!("\x1b[33m[skip] {pkg}: {e}\x1b[0m");
            continue;
        }
        // Apps only installed in another user need that user's `pm path`.
        let user = profile_only.iter().find(|(n, _)| n == pkg).map(|(_, u)| *u);
        let paths = phone.apk_paths(pkg, user).unwrap_or_default();
        for remote in &paths {
            let base = remote.rsplit('/').next().unwrap_or("base.apk");
            let local = appdir.join(base);
            if phone.pull(remote, &local).is_ok() {
                apk_count += 1;
            } else {
                eprintln!("\x1b[33m[warn] {pkg}: pull {remote} failed\x1b[0m");
            }
        }
        acquire_save(&mut phone, &format!("dumpsys package {pkg}"), &appdir.join("dumpsys_package.txt"), &out, &mut collected);
        println!("  \x1b[32m[{:>3}/{}]\x1b[0m {pkg}  \x1b[2m({} apk)\x1b[0m", i + 1, packages.len(), paths.len());
    }

    // ---- Evidence bundle (audit trail auto-includes every pull + shell). ----
    let mut meta = args.case.to_json();
    if let (Some(m), serde_json::Value::Object(o)) = (&args.mandate, &mut meta) {
        o.insert("mandate".into(), json!(m));
    }
    let kind = if args.triage { "device_triage" } else { "device_acquire" };
    match evidence::write_evidence(&out, &phone, kind, identifiers.clone(), &[], collected, meta) {
        Ok((mpath, sha)) => {
            if args.triage {
                println!("\n\x1b[32m✓ Triage done → {}\x1b[0m  \x1b[2m(volatile state, wipe check, identifiers; run a full acquire next)\x1b[0m", out.display());
            } else {
                println!(
                "\n\x1b[32m✓ Acquired {} app(s), {} APK(s) → {}\x1b[0m",
                packages.len(),
                apk_count,
                out.display()
            );
            }
            println!("\x1b[2m  manifest: {}  (sha256 {})\x1b[0m", mpath.display(), &sha[..16]);
        }
        Err(e) => {
            eprintln!("\x1b[31mError writing evidence bundle: {e}\x1b[0m");
            return ExitCode::from(1);
        }
    }

    ExitCode::SUCCESS
}

fn run_device_shell(args: DeviceShellArgs) -> ExitCode {
    let mut phone = match args.conn.connect() {
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

fn run_analyze(args: AnalyzeArgs) -> ExitCode {
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    if !args.path.exists() {
        eprintln!("\x1b[31mError: path not found — {}\x1b[0m", args.path.display());
        return ExitCode::from(1);
    }

    let started_utc = chrono::Utc::now().to_rfc3339();

    let Some(mut iocs) = load_iocs(&args.iocs) else { return ExitCode::from(1) };
    if let Err(e) = media::load_alert_hashsets(&mut iocs, &args.hashes) {
        eprintln!("\x1b[31m{e}\x1b[0m");
        return ExitCode::from(1);
    }
    if iocs.unsupported > 0 {
        eprintln!("\x1b[33m[warn] {} indicator comparison(s) of unsupported types ignored\x1b[0m", iocs.unsupported);
    }
    let is_case = args.path.is_dir() && case::Case::is_case(&args.path);

    // Gather analyzable package files (recursively for a directory).
    let mut files: Vec<PathBuf> = Vec::new();
    if args.path.is_dir() {
        for e in walkdir::WalkDir::new(&args.path).into_iter().filter_map(|e| e.ok()) {
            if e.file_type().is_file() && scanner::detect_app_type(e.path()).is_some() {
                files.push(e.path().to_path_buf());
            }
        }
        files.sort();
    } else if scanner::detect_app_type(&args.path).is_some() {
        files.push(args.path.clone());
    } else {
        eprintln!(
            "\x1b[31mError: unsupported file. Valid extensions: {}\x1b[0m",
            scanner::VALID_EXTENSIONS.join(", ")
        );
        return ExitCode::from(1);
    }

    if files.is_empty() && !is_case && iocs.is_empty() {
        println!("No analyzable packages found under {}.", args.path.display());
        return ExitCode::SUCCESS;
    }

    println!(
        "\x1b[1m\x1b[36mAnalyzing {} package(s) offline from {}…\x1b[0m",
        files.len(),
        args.path.display()
    );

    // Reports must land on disk before the manifest can hash them.
    if let Some(dir) = &args.evidence {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("\x1b[31mcannot create {}: {e}\x1b[0m", dir.display());
            return ExitCode::from(1);
        }
    }

    let mut inputs_meta: Vec<Value> = Vec::new();
    let mut report_paths: Vec<PathBuf> = Vec::new();
    let mut any_fail = false;
    let mut sw_hits: Vec<String> = Vec::new();
    let mut totals: BTreeMap<String, u64> = BTreeMap::new();
    // Per-app triage rows: (label, score, critical, high, stalkerware).
    let mut triage: Vec<(String, i64, u64, u64, bool)> = Vec::new();

    // Scan every package on all cores; reporting below stays sequential and in order.
    let n = files.len();
    let done = std::sync::atomic::AtomicUsize::new(0);
    let scanned = par_map(&files, |f| {
        let r = (
            scanner::compute_hash(f).unwrap_or_default(),
            std::fs::metadata(f).map(|m| m.len()).unwrap_or(0),
            scanner::scan::<fn(&models::Finding)>(f, None),
            adb_checks::stalkerware_cert_findings(f),
        );
        let k = done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        eprint!("\r\x1b[2K\x1b[2m  scanned {k}/{n}\x1b[0m");
        r
    });
    eprint!("\r\x1b[2K");

    for (f, (hash, size, mut result, cert_hits)) in files.iter().zip(scanned) {

        // Offline stalkerware match by declared package name.
        let pkg = result
            .app_info
            .get("package")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut is_sw = false;
        if !pkg.is_empty() && adb_checks::is_stalkerware(&pkg) {
            is_sw = true;
            sw_hits.push(pkg.clone());
            result.findings.push(adb_checks::stalkerware_package_finding(&pkg));
        }
        if !cert_hits.is_empty() && !is_sw {
            is_sw = true;
            sw_hits.push(if pkg.is_empty() { label_of(f, &args.path) } else { pkg.clone() });
        }
        result.findings.extend(cert_hits);

        let label = f
            .strip_prefix(&args.path)
            .unwrap_or(f)
            .to_string_lossy()
            .into_owned();
        print_header(&format!("{label}  [{pkg}]"), "apk");
        for finding in &result.findings {
            print_finding(finding, args.detail);
        }
        print_summary(&result);

        // Aggregate.
        for (k, v) in result.summary() {
            if let Some(n) = v.as_u64() {
                *totals.entry(k).or_insert(0) += n;
            }
        }
        let crit = result.count_sev(models::Severity::Critical);
        let high = result.count_sev(models::Severity::High);
        triage.push((if pkg.is_empty() { label.clone() } else { pkg.clone() }, result.security_score(), crit, high, is_sw));

        inputs_meta.push(json!({
            "file": label,
            "package": pkg,
            "sha256": hash,
            "bytes": size,
        }));

        let want_report = args.json_output || args.evidence.is_some();
        if want_report {
            let base = pkg_or_stem(f, &pkg);
            if args.json_output {
                let dir = args.output.clone().unwrap_or_else(|| PathBuf::from("."));
                if let Ok(p) = export_json(&result, Some(&dir.join(format!("{base}_report.json")))) {
                    println!("\x1b[32mJSON report: {}\x1b[0m", p.display());
                }
            }
            if let Some(edir) = &args.evidence {
                if let Ok(p) = export_json(&result, Some(&edir.join(format!("{base}_report.json")))) {
                    report_paths.push(p);
                }
            }
        }

        if fails_threshold(&result, args.fail_on) {
            any_fail = true;
        }
    }

    // Optional: match a plain installed-apps list against the indicators.
    if let Some(pf) = &args.packages {
        match std::fs::read_to_string(pf) {
            Ok(text) => {
                for line in text.lines() {
                    let p = line.trim().strip_prefix("package:").unwrap_or(line.trim());
                    if !p.is_empty() && adb_checks::is_stalkerware(p) && !sw_hits.contains(&p.to_string()) {
                        sw_hits.push(p.to_string());
                    }
                }
            }
            Err(e) => eprintln!("\x1b[33m[warn] cannot read --packages {}: {e}\x1b[0m", pf.display()),
        }
    }

    // ---- Case-level investigation (acquisition dirs) and IOC matching. ----
    if is_case || !iocs.is_empty() {
        let findings = if is_case {
            let c = case::Case::load(&args.path);
            print_header(&format!("Investigation — {}", args.path.display()), "case");
            println!(
                "\x1b[2m  {} package(s), {} app-op access(es), clock UTC{}{}\x1b[0m\n",
                c.packages.len(),
                c.appops.len(),
                c.utc_offset.as_deref().unwrap_or("?"),
                c.clock_skew_s.map(|s| format!(", skew {s}s")).unwrap_or_default()
            );
            c.findings(&iocs)
        } else {
            print_header(&format!("IOC matching — {}", args.path.display()), "ioc");
            case::ioc_findings(&iocs.scan_dir(&args.path, &[]))
        };
        let mut findings = findings;
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        if findings.is_empty() {
            println!("  \x1b[32mNo investigation findings.\x1b[0m\n");
        }
        for f in &findings {
            print_finding(f, args.detail);
            if let Some(n) = totals.get_mut(f.severity.value()) {
                *n += 1;
            } else {
                totals.insert(f.severity.value().to_string(), 1);
            }
        }
        let report = serde_json::json!({
            "schema_version": 1,
            "kind": "case_investigation",
            "path": args.path.display().to_string(),
            "ioc_sources": iocs.sources.iter().map(|(f, n)| json!({"file": f, "indicators": n})).collect::<Vec<_>>(),
            "findings": findings.iter().map(|f| f.to_json()).collect::<Vec<_>>(),
        });
        let text = serde_json::to_string_pretty(&report).unwrap_or_default();
        let mut targets: Vec<PathBuf> = Vec::new();
        if args.json_output {
            targets.push(args.output.clone().unwrap_or_else(|| PathBuf::from(".")).join("case_report.json"));
        }
        if let Some(edir) = &args.evidence {
            targets.push(edir.join("case_report.json"));
        }
        for t in targets {
            match std::fs::write(&t, &text) {
                Ok(()) => {
                    println!("\x1b[32mJSON report: {}\x1b[0m", t.display());
                    if args.evidence.as_ref().is_some_and(|e| t.starts_with(e)) {
                        report_paths.push(t);
                    }
                }
                Err(e) => eprintln!("\x1b[31mError writing {}: {e}\x1b[0m", t.display()),
            }
        }
        if let Some(fl) = args.fail_on {
            let idx = SEVERITY_ORDER.iter().position(|&s| s == fl.as_str()).unwrap_or(0);
            if findings.iter().any(|f| SEVERITY_ORDER[..=idx].contains(&f.severity.value())) {
                any_fail = true;
            }
        }
    }

    // ---- Aggregate summary across the extraction. ----
    println!("\n\x1b[1m\x1b[36mExtraction summary\x1b[0m ({} package(s))", files.len());
    for sev in models::Severity::ALL {
        let n = totals.get(sev.value()).copied().unwrap_or(0);
        let label = sev.value().to_uppercase();
        if n > 0 {
            println!("  \x1b[{}m{:<10}\x1b[0m {:>6}", sev.ansi(), label, n);
        } else {
            println!("  \x1b[2m{label:<10} {n:>6}\x1b[0m");
        }
    }

    // Triage: worst apps first (stalkerware, then most critical/high, then score).
    triage.sort_by(|a, b| {
        b.4.cmp(&a.4)
            .then(b.2.cmp(&a.2))
            .then(b.3.cmp(&a.3))
            .then(a.1.cmp(&b.1))
    });
    println!("\n\x1b[1mTop-risk packages\x1b[0m");
    for (name, score, crit, high, sw) in triage.iter().take(10) {
        let flag = if *sw { " \x1b[91m[STALKERWARE]\x1b[0m" } else { "" };
        println!("  \x1b[1m{score:>3}/100\x1b[0m  C:{crit} H:{high}  {name}{flag}");
    }

    if !sw_hits.is_empty() {
        sw_hits.sort();
        sw_hits.dedup();
        println!(
            "\n\x1b[91m\x1b[1m[!] {} stalkerware/spyware indicator match(es): {}\x1b[0m",
            sw_hits.len(),
            sw_hits.join(", ")
        );
    }

    // ---- Offline evidence bundle. ----
    if let Some(dir) = &args.evidence {
        match evidence::write_offline_evidence(
            dir,
            &args.path.display().to_string(),
            &started_utc,
            inputs_meta,
            &report_paths,
            args.case.to_json(),
        ) {
            Ok((mpath, sha)) => {
                println!("\n\x1b[32m✓ Evidence bundle: {}\x1b[0m", dir.display());
                println!("\x1b[2m  manifest: {}  (sha256 {})\x1b[0m", mpath.display(), &sha[..16]);
            }
            Err(e) => eprintln!("\x1b[31mError writing evidence bundle: {e}\x1b[0m"),
        }
    }

    if any_fail {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn run_verify(args: VerifyArgs) -> ExitCode {
    let report = match verify::verify_bundle(&args.path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            return ExitCode::from(1);
        }
    };

    print_header(&format!("Verify — {}", args.path.display()), "evidence");

    match report.manifest_ok {
        Some(true) => println!("  \x1b[32m✓ manifest self-hash matches manifest.json.sha256\x1b[0m"),
        Some(false) => println!("  \x1b[91m✗ manifest self-hash MISMATCH — manifest altered\x1b[0m"),
        None => println!("  \x1b[33m• no detached manifest.json.sha256 to check\x1b[0m"),
    }
    println!("  \x1b[32m✓ {} artifact(s) match recorded hashes\x1b[0m", report.matched.len());
    if report.external > 0 {
        println!("  \x1b[2m• {} external input(s) recorded (offline source, not in bundle)\x1b[0m", report.external);
    }
    if !report.missing.is_empty() {
        println!("  \x1b[91m✗ {} recorded artifact(s) MISSING/altered:\x1b[0m", report.missing.len());
        for m in &report.missing {
            println!("      \x1b[91m{m}\x1b[0m");
        }
    }
    if !report.unlisted.is_empty() {
        println!("  \x1b[33m• {} file(s) present but not in manifest (added after acquisition?):\x1b[0m", report.unlisted.len());
        for u in report.unlisted.iter().take(20) {
            println!("      \x1b[33m{u}\x1b[0m");
        }
    }

    println!();
    if report.passed() {
        println!("\x1b[1m\x1b[32mBundle integrity: VERIFIED\x1b[0m\n");
        ExitCode::SUCCESS
    } else {
        println!("\x1b[1m\x1b[91mBundle integrity: FAILED\x1b[0m\n");
        ExitCode::from(1)
    }
}

/// Map `f` over `items` on every core, preserving input order.
fn par_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()).min(items.len().max(1));
    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|sc| {
        for _ in 0..threads {
            sc.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(i) else { break };
                let r = f(item);
                out.lock().unwrap()[i] = Some(r);
            });
        }
    });
    out.into_inner().unwrap().into_iter().map(|r| r.expect("every index is filled")).collect()
}

fn label_of(f: &Path, root: &Path) -> String {
    f.strip_prefix(root).unwrap_or(f).to_string_lossy().into_owned()
}

fn run_timeline(args: TimelineArgs) -> ExitCode {
    if !case::Case::is_case(&args.case) {
        eprintln!("\x1b[31m{} is not a `device acquire` case (no device/packages.txt)\x1b[0m", args.case.display());
        return ExitCode::from(1);
    }
    let c = case::Case::load(&args.case);
    let events = c.timeline();
    let out = args.output.unwrap_or_else(|| args.case.join("timeline.csv"));
    if let Err(e) = case::write_timeline(&c, &events, &out) {
        eprintln!("\x1b[31m{e}\x1b[0m");
        return ExitCode::from(1);
    }
    let mut per: Vec<(String, usize)> = case::per_source(&events).into_iter().collect();
    per.sort();
    println!("\x1b[32m✓ {} event(s) → {}\x1b[0m", events.len(), out.display());
    for (src, n) in per {
        println!("  {src:<18} {n:>7}");
    }
    let skew = c.clock_skew_s.map(|s| format!("; device clock skew {s}s vs host")).unwrap_or_default();
    match (&c.tz, &c.utc_offset) {
        (Some(tz), _) => println!("\x1b[2m  device-local times with per-event offsets ({tz}, DST-aware){skew}\x1b[0m"),
        (None, Some(o)) => println!("\x1b[33m  time zone unknown: capture-time offset UTC{o} applied to every event (wrong across DST){skew}\x1b[0m"),
        (None, None) => println!("\x1b[33m  no time zone or clock info: times are device-local with unknown offset\x1b[0m"),
    }
    ExitCode::SUCCESS
}

fn run_diff(args: DiffArgs) -> ExitCode {
    for c in [&args.old, &args.new] {
        if !case::Case::is_case(c) {
            eprintln!("\x1b[31m{} is not a `device acquire` case (no device/packages.txt)\x1b[0m", c.display());
            return ExitCode::from(1);
        }
    }
    let Some(iocs) = load_iocs(&args.iocs) else { return ExitCode::from(1) };
    let d = diff::diff(&case::Case::load(&args.old), &case::Case::load(&args.new), &iocs);
    if args.json_output || args.output.is_some() {
        let text = serde_json::to_string_pretty(&d).unwrap_or_default();
        match &args.output {
            Some(p) => {
                if let Err(e) = std::fs::write(p, text) {
                    eprintln!("\x1b[31mcannot write {}: {e}\x1b[0m", p.display());
                    return ExitCode::from(1);
                }
                println!("\x1b[32m✓ Diff → {}\x1b[0m", p.display());
            }
            None => println!("{text}"),
        }
    } else {
        diff::print(&d);
    }
    ExitCode::SUCCESS
}

/// `<case>_<suffix>` next to the case directory.
fn sibling(case: &Path, suffix: &str) -> PathBuf {
    let name = case.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "case".into());
    case.with_file_name(format!("{name}_{suffix}"))
}

fn run_comms(args: CommsArgs) -> ExitCode {
    if !case::Case::is_case(&args.case) {
        eprintln!("\x1b[31m{} is not an APEX case\x1b[0m", args.case.display());
        return ExitCode::from(1);
    }
    let c = case::Case::load(&args.case);
    let items = comms::load(&c);
    if items.is_empty() {
        eprintln!("\x1b[33mNo communications in this case: acquire or import it with --mandate <reference>.\x1b[0m");
        return ExitCode::from(1);
    }
    let mandate = std::fs::read_to_string(args.case.join("manifest.json")).ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok()).and_then(|m| m["case"]["mandate"].as_str().map(String::from));
    println!("\x1b[1mCommunications\x1b[0m  \x1b[2m(mandate: {})\x1b[0m", mandate.as_deref().unwrap_or("not recorded"));
    for (k, (n, rec)) in comms::counts(&items) {
        let r = if rec > 0 { format!("  \x1b[33m{rec} recovered from deleted records\x1b[0m") } else { String::new() };
        println!("  {k:<10} {n:>7}{r}");
    }
    let dir = args.output.unwrap_or_else(|| sibling(&args.case, "comms"));
    match comms::export(&c, &items, &dir) {
        Ok(files) => {
            for f in files {
                println!("\x1b[32m✓ {}\x1b[0m", f.display());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            ExitCode::from(1)
        }
    }
}

fn run_media(args: MediaArgs) -> ExitCode {
    if !case::Case::is_case(&args.case) {
        eprintln!("\x1b[31m{} is not an APEX case\x1b[0m", args.case.display());
        return ExitCode::from(1);
    }
    let c = case::Case::load(&args.case);
    if !args.case.join("storage").is_dir() {
        eprintln!("\x1b[33mNo shared storage in this case: acquire or import it with --storage.\x1b[0m");
        return ExitCode::from(1);
    }
    let mut known = std::collections::HashSet::new();
    for f in &args.known {
        match media::load_hashset(f) {
            Ok(h) => {
                eprintln!("\x1b[2mLoaded {} known hash(es) from {}\x1b[0m", h.len(), f.display());
                known.extend(h.into_iter().map(|(_, h, _)| h));
            }
            Err(e) => {
                eprintln!("\x1b[31m{e}\x1b[0m");
                return ExitCode::from(1);
            }
        }
    }
    let mut alert = ioc::IocSet::default();
    if let Err(e) = media::load_alert_hashsets(&mut alert, &args.hashes) {
        eprintln!("\x1b[31m{e}\x1b[0m");
        return ExitCode::from(1);
    }
    let items = media::inventory(&c, &known, &alert);
    let located = items.iter().filter(|i| i.meta.lat.is_some()).count();
    let n_known = items.iter().filter(|i| i.known).count();
    let alerts: Vec<&media::Item> = items.iter().filter(|i| i.alert.is_some()).collect();
    println!("\x1b[1mMedia\x1b[0m  {} file(s), {} with a location, {} known (hash set)", items.len(), located, n_known);
    for a in &alerts {
        println!("  \x1b[31m⚠ {}  {}\x1b[0m", a.rel, a.alert.as_deref().unwrap_or(""));
    }
    let dir = args.output.unwrap_or_else(|| sibling(&args.case, "media"));
    match media::export(&c, &items, &dir) {
        Ok(files) => {
            for f in files {
                println!("\x1b[32m✓ {}\x1b[0m", f.display());
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            ExitCode::from(1)
        }
    }
}

fn run_import(args: ImportArgs) -> ExitCode {
    if args.output.join("manifest.json").exists() {
        eprintln!("\x1b[31m{} already holds a case: pick a new directory\x1b[0m", args.output.display());
        return ExitCode::from(1);
    }
    println!("\x1b[1m\x1b[36mImporting {} → {}\x1b[0m", args.source.display(), args.output.display());
    let mut meta = args.case.to_json();
    if let (Some(m), serde_json::Value::Object(o)) = (&args.mandate, &mut meta) {
        o.insert("mandate".into(), serde_json::json!(m));
    }
    let opts = import::Options { comms: args.mandate.is_some(), storage: args.storage };
    match import::import(&args.source, &args.output, meta, opts) {
        Ok(s) => {
            println!(
                "\x1b[32m✓ {} package(s), {} user-installed, {} APK(s), {} user(s)\x1b[0m  \x1b[2m(extraction root: /{})\x1b[0m",
                s.packages, s.third_party, s.apks, s.users, s.root_prefix
            );
            println!("\x1b[2m  {} file(s) written, hashed in manifest.json\x1b[0m", s.produced.len());
            for m in &s.missing {
                println!("\x1b[33m  not in this extraction: {m}\x1b[0m");
            }
            println!("\x1b[2m  next: apex analyze {0} · apex timeline {0} · apex identifiers {0} · apex report {0}\x1b[0m", args.output.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            ExitCode::from(1)
        }
    }
}

fn run_identifiers(args: IdentifiersArgs) -> ExitCode {
    if !case::Case::is_case(&args.case) {
        eprintln!("\x1b[31m{} is not an APEX case (no device/packages.txt)\x1b[0m", args.case.display());
        return ExitCode::from(1);
    }
    let v = seizure::identifiers(&case::Case::load(&args.case));
    if args.json_output || args.output.is_some() {
        let text = serde_json::to_string_pretty(&v).unwrap_or_default();
        match &args.output {
            Some(p) => {
                if let Err(e) = std::fs::write(p, text) {
                    eprintln!("\x1b[31mcannot write {}: {e}\x1b[0m", p.display());
                    return ExitCode::from(1);
                }
                println!("\x1b[32m✓ Identifiers → {}\x1b[0m", p.display());
            }
            None => println!("{text}"),
        }
    } else {
        seizure::print_identifiers(&v);
    }
    ExitCode::SUCCESS
}

fn run_report(args: ReportArgs) -> ExitCode {
    if !case::Case::is_case(&args.case) {
        eprintln!("\x1b[31m{} is not a `device acquire` case (no device/packages.txt)\x1b[0m", args.case.display());
        return ExitCode::from(1);
    }
    let Some(mut iocs) = load_iocs(&args.iocs) else { return ExitCode::from(1) };
    if let Err(e) = media::load_alert_hashsets(&mut iocs, &args.hashes) {
        eprintln!("\x1b[31m{e}\x1b[0m");
        return ExitCode::from(1);
    }
    let c = case::Case::load(&args.case);
    // Signing-certificate matches need the APKs; the rest comes from the case.
    let apks: Vec<PathBuf> = c.third_party.iter().map(|p| args.case.join("apps").join(p).join("base.apk")).filter(|p| p.is_file()).collect();
    let extra: Vec<models::Finding> = par_map(&apks, |a| adb_checks::stalkerware_cert_findings(a)).into_iter().flatten().collect();
    let html = report::render(&c, &iocs, extra);
    let out = args.output.unwrap_or_else(|| args.case.join("report.html"));
    if let Err(e) = std::fs::write(&out, html) {
        eprintln!("\x1b[31mcannot write {}: {e}\x1b[0m", out.display());
        return ExitCode::from(1);
    }
    println!("\x1b[32m✓ Report → {}\x1b[0m", out.display());
    ExitCode::SUCCESS
}

/// Load STIX2 indicator files; prints the counts, `None` (after printing why) on error.
fn load_iocs(files: &[PathBuf]) -> Option<ioc::IocSet> {
    let mut iocs = ioc::IocSet::default();
    for f in files {
        match iocs.load_stix2(f) {
            Ok(n) => eprintln!("\x1b[2mLoaded {n} indicator(s) from {}\x1b[0m", f.display()),
            Err(e) => {
                eprintln!("\x1b[31m{e}\x1b[0m");
                return None;
            }
        }
    }
    Some(iocs)
}

/// A filesystem-safe report basename: the package name if known, else the file stem.
fn pkg_or_stem(path: &Path, pkg: &str) -> String {
    if !pkg.is_empty() {
        pkg.to_string()
    } else {
        path.file_stem().and_then(|s| s.to_str()).unwrap_or("report").to_string()
    }
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
        match device::usb_devices() {
            Ok(devs) if !devs.is_empty() => {
                let ids: Vec<String> = devs.into_iter().map(|(serial, _)| serial).collect();
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
    let mut phone = match args.conn.connect() {
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

    let mut phone = match args.conn.connect() {
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
    use serde_json::json;

    let mut phone = match args.conn.connect() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("\x1b[31m{e}\x1b[0m");
            return ExitCode::from(1);
        }
    };
    live_wipe_alert(&mut phone);

    // For an evidence run, reports must land on disk to be hashed.
    let evidence_dir = args.evidence.clone();
    if let Some(dir) = &evidence_dir {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("\x1b[31mcannot create {}: {e}\x1b[0m", dir.display());
            return ExitCode::from(1);
        }
    }
    let mut report_paths: Vec<PathBuf> = Vec::new();

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
        result.findings.extend(adb_checks::stalkerware_cert_findings(&local));
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

        // For an evidence run, always persist the per-app report for hashing.
        if let Some(dir) = &evidence_dir {
            let out_path = dir.join(format!("{pkg}_report.json"));
            match export_json(&result, Some(&out_path)) {
                Ok(p) => report_paths.push(p),
                Err(e) => eprintln!("\x1b[31mError writing evidence report for {pkg}: {e}\x1b[0m"),
            }
        }

        if fails_threshold(&result, args.fail_on) {
            any_fail = true;
        }
    }

    println!("\x1b[1mScanned {ok}/{} app(s).\x1b[0m", packages.len());

    if let Some(dir) = &evidence_dir {
        let props = phone.props().unwrap_or_default();
        let pick = |k: &str| props.get(k).cloned().unwrap_or_default();
        let device = json!({
            "model": pick("ro.product.model"),
            "manufacturer": pick("ro.product.manufacturer"),
            "serial": pick("ro.serialno"),
            "android": pick("ro.build.version.release"),
            "sdk": pick("ro.build.version.sdk"),
            "security_patch": pick("ro.build.version.security_patch"),
            "build_fingerprint": pick("ro.build.fingerprint"),
        });
        match evidence::write_evidence(dir, &phone, "device_scan", device, &report_paths, Vec::new(), args.case.to_json()) {
            Ok((mpath, sha)) => {
                println!("\x1b[32m✓ Evidence bundle: {}\x1b[0m", dir.display());
                println!("\x1b[2m  manifest: {}  (sha256 {})\x1b[0m", mpath.display(), &sha[..16]);
            }
            Err(e) => eprintln!("\x1b[31mError writing evidence bundle: {e}\x1b[0m"),
        }
    }

    if any_fail {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod par_tests {
    #[test]
    fn par_map_keeps_order() {
        let v: Vec<u64> = (0..1000).collect();
        assert_eq!(super::par_map(&v, |x| x * 2), v.iter().map(|x| x * 2).collect::<Vec<_>>());
        assert!(super::par_map(&Vec::<u8>::new(), |x| *x).is_empty());
    }
}
