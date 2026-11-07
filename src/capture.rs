//! Screen capture of a conversation on an unlocked phone: what the examiner
//! would read and photograph by hand, automated. For each screen: the UI tree
//! (`uiautomator dump`: every text shown, with its position) and a screenshot;
//! then a swipe toward older content, until the top is reached.
//!
//! Works on any app, end-to-end encrypted ones included, since it reads the
//! screen. Shows only what the app displays: no deleted messages. Apps that set
//! FLAG_SECURE (secret chats…) give black screenshots, but their text is still
//! in the UI tree.

use crate::device::Phone;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const UI: &str = "/data/local/tmp/apex_ui.xml";
const SHOT: &str = "/data/local/tmp/apex_cap.png";

/// One text element on screen.
#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    pub text: String,
    /// From `content-desc` (images, voice notes, icons) rather than `text`.
    pub described: bool,
    pub bounds: [i32; 4],
    pub resource_id: String,
    pub class: String,
}

impl Line {
    /// left / right / center: in chat apps, right is usually the phone's owner.
    pub fn side(&self, width: i32) -> &'static str {
        let c = (self.bounds[0] + self.bounds[2]) / 2;
        if c < width * 45 / 100 {
            "left"
        } else if c > width * 55 / 100 {
            "right"
        } else {
            "center"
        }
    }
}

/// Text elements of one `uiautomator dump`, for `package` only (no status bar,
/// keyboard or system UI), top to bottom.
pub fn parse_ui(xml: &str, package: &str) -> Vec<Line> {
    let Ok(doc) = roxmltree::Document::parse(xml) else { return Vec::new() };
    let mut out = Vec::new();
    for n in doc.descendants().filter(|n| n.has_tag_name("node")) {
        if !package.is_empty() && n.attribute("package") != Some(package) {
            continue;
        }
        let text = n.attribute("text").unwrap_or("").trim();
        let desc = n.attribute("content-desc").unwrap_or("").trim();
        let (t, described) = if !text.is_empty() { (text, false) } else if !desc.is_empty() { (desc, true) } else { continue };
        let b: Vec<i32> = n.attribute("bounds").unwrap_or("").split(|c: char| !c.is_ascii_digit() && c != '-').filter_map(|x| x.parse().ok()).collect();
        let Ok(bounds) = <[i32; 4]>::try_from(b) else { continue };
        if bounds[3] <= bounds[1] {
            continue;
        }
        out.push(Line { text: t.to_string(), described, bounds, resource_id: n.attribute("resource-id").unwrap_or("").to_string(), class: n.attribute("class").unwrap_or("").to_string() });
    }
    out.sort_by_key(|l| (l.bounds[1], l.bounds[0]));
    out
}

/// Merge pages captured newest-first into one oldest-first sequence, dropping
/// the overlap between consecutive screens. Returns (page index, line).
pub fn merge(pages: &[Vec<Line>]) -> Vec<(usize, Line)> {
    let mut out: Vec<(usize, Line)> = Vec::new();
    for (i, page) in pages.iter().enumerate().rev() {
        // Largest k: the last k merged texts equal the first k of this page.
        let max = out.len().min(page.len());
        let k = (1..=max)
            .rev()
            .find(|&k| out[out.len() - k..].iter().zip(&page[..k]).all(|((_, a), b)| a.text == b.text))
            .unwrap_or(0);
        out.extend(page[k..].iter().map(|l| (i, l.clone())));
    }
    out
}

pub struct Options {
    pub max_pages: usize,
    pub settle_ms: u64,
    pub label: Option<String>,
}

pub struct Result_ {
    pub package: String,
    pub pages: usize,
    pub lines: usize,
    pub collected: Vec<Value>,
    pub reports: Vec<PathBuf>,
}

fn screen_size(phone: &mut Phone) -> (i32, i32) {
    let t = phone.run("wm size").unwrap_or_default();
    // "Override size" wins over "Physical size".
    let pick = |key: &str| t.lines().find(|l| l.contains(key)).and_then(|l| l.rsplit(' ').next()).and_then(|s| s.split_once('x')).and_then(|(w, h)| Some((w.trim().parse().ok()?, h.trim().parse().ok()?)));
    pick("Override").or_else(|| pick("Physical")).unwrap_or((1080, 2400))
}

/// Package of the window in front.
pub fn foreground(phone: &mut Phone) -> String {
    let t = phone.run("dumpsys window | grep mCurrentFocus").unwrap_or_default();
    t.split_whitespace().find_map(|w| w.split('/').next().filter(|p| p.contains('.') && !p.starts_with('{'))).unwrap_or("").trim_end_matches('}').to_string()
}

fn hash(p: &Path) -> String {
    crate::scanner::compute_hash(p).unwrap_or_default()
}

/// Capture the conversation on screen into `out`.
pub fn run(phone: &mut Phone, out: &Path, opts: &Options) -> Result<Result_, String> {
    let package = foreground(phone);
    if package.is_empty() {
        return Err("no app in front: unlock the phone and open the conversation to capture".into());
    }
    // Scrolling needs input injection; Xiaomi (MIUI / HyperOS) refuses it unless
    // "USB debugging (Security settings)" is on. KEYCODE_UNKNOWN does nothing on screen.
    let probe = phone.run("input keyevent 0 2>&1").unwrap_or_default();
    if probe.contains("INJECT_EVENTS") || probe.contains("SecurityException") {
        return Err("the phone refuses simulated touches (INJECT_EVENTS). On Xiaomi / Redmi / POCO: Developer options → enable \"USB debugging (Security settings)\" (needs a Mi account; note the change for the PV), then retry".into());
    }
    let pages_dir = out.join("pages");
    std::fs::create_dir_all(&pages_dir).map_err(|e| format!("{}: {e}", pages_dir.display()))?;
    let (w, h) = screen_size(phone);
    let mut collected = Vec::new();
    let mut pages: Vec<Vec<Line>> = Vec::new();
    let mut times: Vec<String> = Vec::new();
    for i in 0..opts.max_pages {
        let n = i + 1;
        // MIUI prints Java noise on stderr; the dump file is what counts.
        let _ = phone.run(&format!("rm -f {UI}; uiautomator dump {UI} >/dev/null 2>&1"));
        let xml = phone.run(&format!("cat {UI}")).unwrap_or_default();
        if !xml.contains("<hierarchy") {
            return Err(format!("screen {n}: uiautomator dump failed (screen off, or the app is animating: retry)"));
        }
        let xml_path = pages_dir.join(format!("{n:04}.xml"));
        std::fs::write(&xml_path, &xml).map_err(|e| e.to_string())?;
        collected.push(json!({"file": format!("pages/{n:04}.xml"), "sha256": hash(&xml_path), "bytes": xml.len(), "source_cmd": format!("uiautomator dump {UI}")}));
        let png_path = pages_dir.join(format!("{n:04}.png"));
        if phone.run(&format!("screencap -p {SHOT}")).is_ok() && phone.pull(SHOT, &png_path).is_ok() {
            collected.push(json!({"file": format!("pages/{n:04}.png"), "sha256": hash(&png_path), "bytes": std::fs::metadata(&png_path).map(|m| m.len()).unwrap_or(0), "source_cmd": format!("screencap -p {SHOT}")}));
        }
        times.push(chrono::Utc::now().to_rfc3339());
        let lines = parse_ui(&xml, &package);
        eprint!("\r\x1b[2K  screen {n}  ({} text element(s))", lines.len());
        // The top of the conversation: the screen did not change after a swipe.
        let top = pages.last().is_some_and(|prev| prev.iter().map(|l| &l.text).eq(lines.iter().map(|l| &l.text)));
        pages.push(lines);
        if top {
            break;
        }
        // Finger moves down: the list scrolls toward older messages.
        let _ = phone.run(&format!("input swipe {} {} {} {} 450", w / 2, h * 30 / 100, w / 2, h * 78 / 100));
        std::thread::sleep(std::time::Duration::from_millis(opts.settle_ms));
    }
    eprintln!();
    let _ = phone.run(&format!("rm -f {UI} {SHOT}"));

    let merged = merge(&pages);
    let reports = write_outputs(out, &package, opts, w, &pages, &times, &merged)?;
    Ok(Result_ { package, pages: pages.len(), lines: merged.len(), collected, reports })
}

fn write_outputs(out: &Path, package: &str, opts: &Options, width: i32, pages: &[Vec<Line>], times: &[String], merged: &[(usize, Line)]) -> Result<Vec<PathBuf>, String> {
    // transcript.txt: oldest first, with the screen each line was read on.
    let mut t = format!("# APEX screen capture: {package}{}\n# {} screen(s), oldest first. [screen] side | text   (right is usually the phone's owner; * = description of an image or icon)\n\n", opts.label.as_deref().map(|l| format!(" — {l}")).unwrap_or_default(), pages.len());
    for (p, l) in merged {
        t.push_str(&format!("[{:04}] {:<6} | {}{}\n", p + 1, l.side(width), if l.described { "* " } else { "" }, l.text.replace('\n', "\n                | ")));
    }
    let tp = out.join("transcript.txt");
    std::fs::write(&tp, t).map_err(|e| e.to_string())?;

    // capture.db, for SQL queries.
    let dbp = out.join("capture.db");
    let _ = std::fs::remove_file(&dbp);
    let c = rusqlite::Connection::open(&dbp).map_err(|e| e.to_string())?;
    let r = (|| -> rusqlite::Result<()> {
        c.execute_batch(
            "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
             CREATE TABLE screens(
               screen INTEGER PRIMARY KEY,   -- 1 = first screen captured (newest content)
               time_utc TEXT,                -- when it was captured
               png TEXT, xml TEXT            -- files under pages/
             );
             CREATE TABLE lines(
               seq INTEGER PRIMARY KEY,      -- reading order, oldest first, overlap between screens removed
               screen INTEGER REFERENCES screens(screen),
               side TEXT,                    -- left / right / center (right: usually the phone's owner)
               text TEXT,
               described INTEGER,            -- 1 = description of an image, voice note or icon
               x1 INTEGER, y1 INTEGER, x2 INTEGER, y2 INTEGER,
               resource_id TEXT, class TEXT
             );
             CREATE TABLE screen_lines(      -- every element of every screen, before merging
               screen INTEGER, pos INTEGER, text TEXT, described INTEGER,
               x1 INTEGER, y1 INTEGER, x2 INTEGER, y2 INTEGER, resource_id TEXT, class TEXT
             );
             BEGIN;",
        )?;
        for (k, v) in [("package", package.to_string()), ("label", opts.label.clone().unwrap_or_default()), ("screen_width", width.to_string()), ("screens", pages.len().to_string())] {
            c.execute("INSERT INTO meta VALUES (?1, ?2)", rusqlite::params![k, v])?;
        }
        for (i, page) in pages.iter().enumerate() {
            let n = i + 1;
            c.execute("INSERT INTO screens VALUES (?1, ?2, ?3, ?4)", rusqlite::params![n as i64, times.get(i), format!("pages/{n:04}.png"), format!("pages/{n:04}.xml")])?;
            for (pos, l) in page.iter().enumerate() {
                c.execute(
                    "INSERT INTO screen_lines VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                    rusqlite::params![n as i64, pos as i64, l.text, l.described as i64, l.bounds[0], l.bounds[1], l.bounds[2], l.bounds[3], l.resource_id, l.class],
                )?;
            }
        }
        for (seq, (p, l)) in merged.iter().enumerate() {
            c.execute(
                "INSERT INTO lines VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                rusqlite::params![seq as i64 + 1, *p as i64 + 1, l.side(width), l.text, l.described as i64, l.bounds[0], l.bounds[1], l.bounds[2], l.bounds[3], l.resource_id, l.class],
            )?;
        }
        c.execute_batch("COMMIT")
    })();
    r.map_err(|e| format!("{}: {e}", dbp.display()))?;
    Ok(vec![tp, dbp])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(t: &str) -> Line {
        Line { text: t.into(), described: false, bounds: [0, 0, 10, 10], resource_id: String::new(), class: String::new() }
    }

    #[test]
    fn ui_parsing() {
        let xml = r#"<?xml version='1.0' encoding='UTF-8' standalone='yes' ?><hierarchy rotation="0">
<node text="" package="com.whatsapp" content-desc="" bounds="[0,0][1080,2400]" resource-id="" class="android.widget.FrameLayout">
<node text="On se voit ce soir ?" package="com.whatsapp" content-desc="" bounds="[40,900][700,980]" resource-id="com.whatsapp:id/message_text" class="android.widget.TextView"/>
<node text="" package="com.whatsapp" content-desc="Voice message, 0:12" bounds="[500,1100][1040,1200]" resource-id="" class="android.view.View"/>
<node text="Oui, 20h" package="com.whatsapp" content-desc="" bounds="[600,1000][1040,1080]" resource-id="com.whatsapp:id/message_text" class="android.widget.TextView"/>
<node text="12:04" package="com.android.systemui" content-desc="" bounds="[0,0][100,50]" resource-id="" class="android.widget.TextView"/>
</node></hierarchy>"#;
        let v = parse_ui(xml, "com.whatsapp");
        assert_eq!(v.iter().map(|x| x.text.as_str()).collect::<Vec<_>>(), vec!["On se voit ce soir ?", "Oui, 20h", "Voice message, 0:12"]);
        assert_eq!((v[0].side(1080), v[1].side(1080)), ("left", "right"));
        assert!(v[2].described);
    }

    #[test]
    fn merging_overlapping_screens() {
        // Captured newest first: screen 1 is the bottom of the conversation.
        let pages = vec![vec![l("c"), l("d"), l("e")], vec![l("a"), l("b"), l("c"), l("d")], vec![l("a"), l("b")]];
        let m: Vec<String> = merge(&pages).into_iter().map(|(_, x)| x.text).collect();
        assert_eq!(m, vec!["a", "b", "c", "d", "e"]);
    }
}
