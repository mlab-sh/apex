//! ELF parsing helpers (checksec, symbols, sections, strings) via goblin.

use goblin::elf::Elf;
use std::path::Path;

pub struct ElfInfo {
    pub nx: bool,
    pub pie: bool,
    pub canary: bool,
    pub relro: String,
    pub rpath: bool,
    pub stripped: bool,
    pub fortified: usize,
    pub unsafe_funcs: Vec<String>,
    pub exported: Vec<String>,
    pub imported: Vec<String>,
    pub sections: Vec<String>,
}

const PT_INTERP: u32 = 3;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PF_X: u32 = 1;
const ET_DYN: u16 = 3;
const DT_RPATH: u64 = 15;
const DT_RUNPATH: u64 = 29;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;
const SHN_UNDEF: usize = 0;

const UNSAFE_FUNCS: &[&str] = &[
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strncat", "sprintf", "snprintf",
    "vsprintf", "vsnprintf", "gets", "fprintf",
];

pub fn parse_file(path: &Path) -> Option<(Vec<u8>, ElfInfo)> {
    let bytes = std::fs::read(path).ok()?;
    let info = parse_bytes(&bytes)?;
    Some((bytes, info))
}

pub fn parse_bytes(bytes: &[u8]) -> Option<ElfInfo> {
    let elf = Elf::parse(bytes).ok()?;

    let has_gnu_stack_nx = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_STACK && (ph.p_flags & PF_X) == 0);

    let has_interp = elf.program_headers.iter().any(|ph| ph.p_type == PT_INTERP);
    let pie = elf.header.e_type == ET_DYN && has_interp;

    let mut exported = Vec::new();
    let mut imported = Vec::new();
    for sym in elf.dynsyms.iter() {
        let name = elf.dynstrtab.get_at(sym.st_name).unwrap_or("");
        if name.is_empty() {
            continue;
        }
        if sym.st_shndx == SHN_UNDEF {
            imported.push(name.to_string());
        } else {
            exported.push(name.to_string());
        }
    }

    let canary = imported
        .iter()
        .any(|s| s == "__stack_chk_fail" || s == "__stack_chk_guard");

    // RELRO
    let mut has_relro = elf
        .program_headers
        .iter()
        .any(|ph| ph.p_type == PT_GNU_RELRO);
    let mut bind_now = false;
    if let Some(dyn_) = &elf.dynamic {
        for d in &dyn_.dyns {
            if d.d_tag == DT_FLAGS && (d.d_val & DF_BIND_NOW) != 0 {
                bind_now = true;
            }
            if d.d_tag == DT_FLAGS_1 && (d.d_val & DF_1_NOW) != 0 {
                bind_now = true;
            }
        }
    }
    // (already computed has_relro from program headers)
    let _ = &mut has_relro;
    let relro = if has_relro && bind_now {
        "full"
    } else if has_relro {
        "partial"
    } else {
        "none"
    }
    .to_string();

    let rpath = !elf.rpaths.is_empty() || !elf.runpaths.is_empty();
    let _ = (DT_RPATH, DT_RUNPATH);

    let sections: Vec<String> = elf
        .section_headers
        .iter()
        .filter_map(|sh| elf.shdr_strtab.get_at(sh.sh_name).map(|s| s.to_string()))
        .collect();
    let stripped = !sections.iter().any(|s| s == ".symtab");

    let fortified = imported.iter().filter(|s| s.ends_with("_chk")).count();
    let mut unsafe_funcs: Vec<String> = imported
        .iter()
        .filter(|s| UNSAFE_FUNCS.contains(&s.as_str()))
        .cloned()
        .collect();
    unsafe_funcs.sort();
    unsafe_funcs.dedup();

    Some(ElfInfo {
        nx: has_gnu_stack_nx,
        pie,
        canary,
        relro,
        rpath,
        stripped,
        fortified,
        unsafe_funcs,
        exported,
        imported,
        sections,
    })
}

/// Extract printable ASCII strings (runs of bytes in [32,127)) of `min_length`.
pub fn extract_strings(bytes: &[u8], min_length: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    for &b in bytes {
        if (32..127).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= min_length {
                strings.push(String::from_utf8_lossy(&current).into_owned());
            }
            current.clear();
        }
    }
    if current.len() >= min_length {
        strings.push(String::from_utf8_lossy(&current).into_owned());
    }
    strings
}
