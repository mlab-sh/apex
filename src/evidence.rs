//! Forensic evidence trail for on-device (ADB) operations.
//!
//! Writes, next to a device report, a tamper-evident record an investigator can
//! rely on: an `audit.jsonl` of every ADB action (UTC-timestamped, each with the
//! SHA-256 of its raw output) and a `manifest.json` tying it together — tool
//! version, device identifiers, acquired-artifact hashes, report hash, and an
//! explicit statement of how the acquisition alters the device.
//!
//! Scope note: this documents and hashes what APEX did; it is **not** a forensic
//! image and captures no app-private data, deleted content, or physical dump.

use crate::device::Phone;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Static, honest description of what a live ADB acquisition touches.
fn alteration_notes() -> Vec<&'static str> {
    vec![
        "Acquisition is LIVE: the device is powered on and USB debugging is authorized. Connecting and running shell commands alters volatile state (spawns shell processes, updates usage statistics and logs).",
        "APEX issues read-oriented commands (getprop, getenforce, settings get/list, pm list, pm path, dumpsys, cmd, ps, ls, cat /proc/net/*, logcat -d, and the read-only getters 1-16 of `service call iphonesubinfo` for IMEI / IMSI / ICCID / line number). Under `--mandate` it also reads the SMS / MMS / call-log / contacts providers (`content query`, `content read` for MMS attachments), and `--storage` pulls shared storage and file pulls. It installs nothing and changes no setting.",
        "`device acquire` writes to the device in two places only: `bugreportz` leaves its zip in the shell user's bugreports directory (not deleted), and the screenshot is written to /data/local/tmp/apex_screen.png, pulled, then removed (skip with --no-screenshot / --no-bugreport). Both are visible in audit.jsonl.",
        "Every command issued is recorded in audit.jsonl with a UTC timestamp and the SHA-256 of its raw output; acquired files are hashed on pull.",
        "This is NOT a forensic image: it does not capture app-private data (/data/data), deleted content, or a physical/file-system image. Use a validated acquisition tool for evidential imaging.",
    ]
}

/// Honest description of an offline analysis over an existing extraction.
fn offline_notes() -> Vec<&'static str> {
    vec![
        "Offline analysis of an existing extraction: no device was contacted. Every input file is opened read-only and hashed (SHA-256); APEX does not modify the extraction.",
        "Findings come from static analysis of package contents. Package-name matches against the stalkerware indicator set are exact-name — strong indicators, not proof.",
        "APEX does not interpret proprietary extraction container formats (e.g. Cellebrite UFDR); point it at a directory tree of package files (unpack the container first).",
    ]
}

/// Write an evidence bundle for an **offline** `analyze` run: a `manifest.json`
/// hashing every input file and every report, plus a detached manifest hash.
/// `inputs` are `{file, sha256, bytes}` objects for each analyzed package.
pub fn write_offline_evidence(
    dir: &Path,
    source: &str,
    started_utc: &str,
    inputs: Vec<Value>,
    report_paths: &[PathBuf],
    case: Value,
) -> Result<(PathBuf, String), String> {
    write_bundle(dir, "offline_analyze", offline_notes(), source, started_utc, inputs, report_paths, case)
}

/// What `apex import` does to (and derives from) an extraction.
fn import_notes() -> Vec<&'static str> {
    vec![
        "Import of an existing full file-system extraction: no device was contacted. The extraction is only read; every source file used is listed in `inputs` with its SHA-256.",
        "The files under device/ are derived from the extraction (system XML in text or ABX form, SQLite account databases opened from a temporary copy, build and persistent properties), rewritten in the text format APEX's analysers read. They are listed in `reports` with their SHA-256. APKs under apps/ are byte-for-byte copies.",
        "Stored Wi-Fi passwords are not copied. Communication databases (SMS / MMS, calls, contacts, WhatsApp, Telegram, Chrome) are copied only with `--mandate`, together with their WAL so deleted rows can be recovered; shared storage only with `--storage`.",
        "File times in the storage listings come from the archive metadata, which depends on the extraction tool.",
    ]
}

/// Evidence bundle for `apex import`.
pub fn write_import_evidence(dir: &Path, source: &str, started_utc: &str, inputs: Vec<Value>, produced: &[PathBuf], case: Value) -> Result<(PathBuf, String), String> {
    write_bundle(dir, "ffs_import", import_notes(), source, started_utc, inputs, produced, case)
}

#[allow(clippy::too_many_arguments)]
fn write_bundle(
    dir: &Path,
    operation: &str,
    notes: Vec<&'static str>,
    source: &str,
    started_utc: &str,
    inputs: Vec<Value>,
    report_paths: &[PathBuf],
    case: Value,
) -> Result<(PathBuf, String), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    let mut reports = Vec::new();
    for p in report_paths {
        let bytes = std::fs::read(p).map_err(|e| format!("cannot read report {}: {e}", p.display()))?;
        let name = p.strip_prefix(dir).ok().map(|r| r.to_string_lossy().into_owned());
        reports.push(json!({
            "file": name.unwrap_or_else(|| p.file_name().and_then(|s| s.to_str()).unwrap_or_default().to_string()),
            "sha256": sha256_hex(&bytes),
            "bytes": bytes.len(),
        }));
    }

    let mut manifest = Map::new();
    manifest.insert("schema_version".into(), json!(1));
    manifest.insert("kind".into(), json!("apex_evidence_manifest"));
    manifest.insert("operation".into(), json!(operation));
    manifest.insert(
        "tool".into(),
        json!({ "name": "apex", "version": env!("CARGO_PKG_VERSION") }),
    );
    manifest.insert(
        "session".into(),
        json!({
            "started_utc": started_utc,
            "ended_utc": chrono::Utc::now().to_rfc3339(),
            "source": source,
            "input_count": inputs.len(),
        }),
    );
    manifest.insert("case".into(), case);
    manifest.insert("methodology".into(), json!(notes));
    manifest.insert("inputs".into(), json!(inputs));
    manifest.insert("reports".into(), json!(reports));

    let manifest_val = Value::Object(manifest);
    let text = serde_json::to_string_pretty(&manifest_val)
        .map_err(|e| format!("cannot serialize manifest: {e}"))?;
    let manifest_sha = sha256_hex(text.as_bytes());
    let manifest_path = dir.join("manifest.json");
    std::fs::write(&manifest_path, &text).map_err(|e| format!("cannot write manifest: {e}"))?;
    std::fs::write(dir.join("manifest.json.sha256"), format!("{manifest_sha}  manifest.json\n"))
        .map_err(|e| format!("cannot write manifest hash: {e}"))?;

    Ok((manifest_path, manifest_sha))
}

/// Write `audit.jsonl` + `manifest.json` into `dir`. `report_paths` are the
/// report files already written by the caller (hashed and referenced here).
/// Returns the manifest path and its SHA-256.
pub fn write_evidence(
    dir: &Path,
    phone: &Phone,
    kind: &str,
    device: Value,
    report_paths: &[PathBuf],
    collected: Vec<Value>,
    case: Value,
) -> Result<(PathBuf, String), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    // audit.jsonl — one JSON object per action, in order.
    let mut audit_text = String::new();
    for e in phone.audit() {
        audit_text.push_str(&serde_json::to_string(&e.to_json()).unwrap_or_default());
        audit_text.push('\n');
    }
    let audit_path = dir.join("audit.jsonl");
    std::fs::write(&audit_path, &audit_text)
        .map_err(|e| format!("cannot write audit log: {e}"))?;
    let audit_sha = sha256_hex(audit_text.as_bytes());

    // Artifacts acquired = the pull actions in the audit trail, plus any
    // caller-collected files (e.g. dumpsys/logcat text saved to disk).
    let mut artifacts: Vec<Value> = phone
        .audit()
        .iter()
        .filter(|e| e.action.starts_with("pull:"))
        .map(|e| {
            json!({
                "action": e.action,
                "sha256": e.output_sha256,
                "bytes": e.output_bytes,
                "ts_utc": e.ts_utc,
            })
        })
        .collect();
    artifacts.extend(collected);

    // Reports written by the caller, hashed for integrity.
    let mut reports = Vec::new();
    for p in report_paths {
        let bytes = std::fs::read(p).map_err(|e| format!("cannot read report {}: {e}", p.display()))?;
        reports.push(json!({
            "file": p.file_name().and_then(|s| s.to_str()).unwrap_or_default(),
            "sha256": sha256_hex(&bytes),
            "bytes": bytes.len(),
        }));
    }

    let mut manifest = Map::new();
    manifest.insert("schema_version".into(), json!(1));
    manifest.insert("kind".into(), json!("apex_evidence_manifest"));
    manifest.insert("operation".into(), json!(kind));
    manifest.insert(
        "tool".into(),
        json!({ "name": "apex", "version": env!("CARGO_PKG_VERSION") }),
    );
    manifest.insert(
        "session".into(),
        json!({
            "started_utc": phone.session_start_utc(),
            "ended_utc": chrono::Utc::now().to_rfc3339(),
            "transport": format!("adb_client {} (direct, no adb server)", phone.transport),
            "adb_key": phone.adb_key.display().to_string(),
            "command_count": phone.audit().len(),
        }),
    );
    manifest.insert("case".into(), case);
    manifest.insert("device".into(), device);
    manifest.insert("methodology".into(), json!(alteration_notes()));
    manifest.insert("artifacts".into(), json!(artifacts));
    manifest.insert("reports".into(), json!(reports));
    manifest.insert(
        "audit_log".into(),
        json!({ "file": "audit.jsonl", "sha256": audit_sha }),
    );

    let manifest_val = Value::Object(manifest);
    let text = serde_json::to_string_pretty(&manifest_val)
        .map_err(|e| format!("cannot serialize manifest: {e}"))?;
    let manifest_sha = sha256_hex(text.as_bytes());
    let manifest_path = dir.join("manifest.json");
    std::fs::write(&manifest_path, &text).map_err(|e| format!("cannot write manifest: {e}"))?;
    // Detached hash of the manifest, so the whole bundle is tamper-evident.
    std::fs::write(dir.join("manifest.json.sha256"), format!("{manifest_sha}  manifest.json\n"))
        .map_err(|e| format!("cannot write manifest hash: {e}"))?;

    Ok((manifest_path, manifest_sha))
}
