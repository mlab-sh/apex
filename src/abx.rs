//! Android system XML files, text or binary.
//!
//! Since Android 12 the framework writes `packages.xml`, `settings_*.xml`,
//! `device_policies.xml`… in **ABX** (Android Binary XML, `BinaryXmlSerializer`):
//! magic `ABX\0`, then one byte per token (low nibble = XmlPullParser event,
//! high nibble = value type), big-endian numbers, `u16`-length modified UTF-8
//! strings, and an interned-string table for tag / attribute names.
//! Both forms parse into the same small tree; typed values are rendered as
//! `abx2xml` would (ints decimal, `*_HEX` lowercase hex, booleans `true`/`false`).

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Elem {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Elem>,
    pub text: String,
}

impl Elem {
    pub fn attr(&self, k: &str) -> Option<&str> {
        self.attrs.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str())
    }

    /// Every descendant element named `name` (depth-first).
    pub fn all<'a>(&'a self, name: &str) -> Vec<&'a Elem> {
        let mut out = Vec::new();
        fn walk<'a>(e: &'a Elem, name: &str, out: &mut Vec<&'a Elem>) {
            for c in &e.children {
                if c.name == name {
                    out.push(c);
                }
                walk(c, name, out);
            }
        }
        walk(self, name, &mut out);
        out
    }

    pub fn child(&self, name: &str) -> Option<&Elem> {
        self.children.iter().find(|c| c.name == name)
    }
}

/// Parse text or binary XML. Returns a synthetic root whose children are the
/// document's top-level elements.
pub fn parse(bytes: &[u8]) -> Result<Elem, String> {
    if bytes.starts_with(b"ABX\0") {
        parse_abx(&bytes[4..])
    } else {
        parse_text(&String::from_utf8_lossy(bytes))
    }
}

fn parse_text(text: &str) -> Result<Elem, String> {
    let doc = roxmltree::Document::parse(text).map_err(|e| format!("XML: {e}"))?;
    fn conv(n: roxmltree::Node) -> Elem {
        Elem {
            name: n.tag_name().name().to_string(),
            attrs: n.attributes().map(|a| (a.name().to_string(), a.value().to_string())).collect(),
            children: n.children().filter(|c| c.is_element()).map(conv).collect(),
            text: n.children().filter(|c| c.is_text()).filter_map(|c| c.text()).collect::<String>().trim().to_string(),
        }
    }
    Ok(Elem { children: vec![conv(doc.root_element())], ..Default::default() })
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
    interned: Vec<String>,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        let s = self.b.get(self.i..self.i + n).ok_or("ABX: truncated")?;
        self.i += n;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn utf(&mut self) -> Result<String, String> {
        let n = self.u16()? as usize;
        // ponytail: modified UTF-8 read as UTF-8; only NUL and supplementary chars differ.
        Ok(String::from_utf8_lossy(self.take(n)?).into_owned())
    }
    fn interned(&mut self) -> Result<String, String> {
        let idx = self.u16()?;
        if idx == 0xFFFF {
            let s = self.utf()?;
            self.interned.push(s.clone());
            Ok(s)
        } else {
            self.interned.get(idx as usize).cloned().ok_or_else(|| format!("ABX: bad interned index {idx}"))
        }
    }
    /// A typed value as text.
    fn value(&mut self, ty: u8) -> Result<String, String> {
        Ok(match ty {
            1 => String::new(),
            2 => self.utf()?,
            3 => self.interned()?,
            4 | 5 => {
                let n = self.u16()? as usize;
                let b = self.take(n)?;
                if ty == 4 {
                    b.iter().map(|x| format!("{x:02x}")).collect()
                } else {
                    base64(b)
                }
            }
            6 => i32::from_be_bytes(self.take(4)?.try_into().unwrap()).to_string(),
            7 => format!("{:x}", u32::from_be_bytes(self.take(4)?.try_into().unwrap())),
            8 => i64::from_be_bytes(self.take(8)?.try_into().unwrap()).to_string(),
            9 => format!("{:x}", u64::from_be_bytes(self.take(8)?.try_into().unwrap())),
            10 => f32::from_be_bytes(self.take(4)?.try_into().unwrap()).to_string(),
            11 => f64::from_be_bytes(self.take(8)?.try_into().unwrap()).to_string(),
            12 => "true".into(),
            13 => "false".into(),
            t => return Err(format!("ABX: unknown type {t}")),
        })
    }
}

fn base64(b: &[u8]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for k in 0..4 {
            s.push(if k <= c.len() { A[(n >> (18 - 6 * k) & 63) as usize] as char } else { '=' });
        }
    }
    s
}

fn parse_abx(b: &[u8]) -> Result<Elem, String> {
    let mut r = Reader { b, i: 0, interned: Vec::new() };
    let mut stack: Vec<Elem> = vec![Elem::default()];
    while r.i < b.len() {
        let t = r.take(1)?[0];
        let (cmd, ty) = (t & 0x0F, t >> 4);
        match cmd {
            0 | 1 => {} // start / end document
            2 => stack.push(Elem { name: r.interned()?, ..Default::default() }),
            3 => {
                r.interned()?;
                let e = stack.pop().ok_or("ABX: unbalanced end tag")?;
                stack.last_mut().ok_or("ABX: unbalanced end tag")?.children.push(e);
            }
            15 => {
                let name = r.interned()?;
                let v = r.value(ty)?;
                stack.last_mut().unwrap().attrs.push((name, v));
            }
            // text, cdata, entity ref, whitespace, PI, comment, doctype
            4..=10 => {
                let v = r.value(ty)?;
                let t = &mut stack.last_mut().unwrap().text;
                match cmd {
                    4 | 5 => t.push_str(&v),
                    // `xml2abx` keeps `&quot;` etc. as entity tokens; the framework writes plain text.
                    6 => t.push_str(match v.as_str() {
                        "quot" => "\"",
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "apos" => "'",
                        _ => "",
                    }),
                    _ => {}
                }
            }
            c => return Err(format!("ABX: unknown token {c} at {}", r.i - 1)),
        }
    }
    if stack.len() != 1 {
        return Err("ABX: unclosed elements".into());
    }
    Ok(stack.pop().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes produced by the phone's own `xml2abx` (Android 13) from
    /// `<packages><package name="com.a" codePath="/data/app/x" it="18d0a1b2c3d" flags="1" userId="10123" /><t>hé</t></packages>`.
    const REAL: &[u8] = &[
        0x41, 0x42, 0x58, 0x00, 0x10, 0x27, 0x00, 0x01, 0x0a, 0x32, 0xff, 0xff, 0x00, 0x08, b'p', b'a', b'c', b'k', b'a', b'g', b'e', b's', 0x32, 0xff, 0xff, 0x00, 0x07, b'p',
        b'a', b'c', b'k', b'a', b'g', b'e', 0x2f, 0xff, 0xff, 0x00, 0x04, b'n', b'a', b'm', b'e', 0x00, 0x05, b'c', b'o', b'm', b'.', b'a', 0x2f, 0xff, 0xff, 0x00, 0x08,
        b'c', b'o', b'd', b'e', b'P', b'a', b't', b'h', 0x00, 0x0b, b'/', b'd', b'a', b't', b'a', b'/', b'a', b'p', b'p', b'/', b'x', 0x2f, 0xff, 0xff, 0x00, 0x02, b'i',
        b't', 0x00, 0x0b, b'1', b'8', b'd', b'0', b'a', b'1', b'b', b'2', b'c', b'3', b'd', 0x2f, 0xff, 0xff, 0x00, 0x05, b'f', b'l', b'a', b'g', b's', 0x00, 0x01, b'1',
        0x2f, 0xff, 0xff, 0x00, 0x06, b'u', b's', b'e', b'r', b'I', b'd', 0x00, 0x05, b'1', b'0', b'1', b'2', b'3', 0x33, 0x00, 0x01, 0x32, 0xff, 0xff, 0x00, 0x01, b't',
        0x24, 0x00, 0x03, b'h', 0xc3, 0xa9, 0x33, 0x00, 0x07, 0x33, 0x00, 0x00, 0x27, 0x00, 0x01, 0x0a, 0x11,
    ];

    #[test]
    fn real_xml2abx() {
        let root = parse(REAL).unwrap();
        let p = &root.all("package")[0];
        assert_eq!(p.attr("name"), Some("com.a"));
        assert_eq!(p.attr("it"), Some("18d0a1b2c3d"));
        assert_eq!(p.attr("userId"), Some("10123"));
        assert_eq!(root.all("t")[0].text, "hé");
        // Same tree from the text form.
        let t = parse(r#"<?xml version="1.0"?><packages><package name="com.a" codePath="/data/app/x" it="18d0a1b2c3d" flags="1" userId="10123" /><t>hé</t></packages>"#.as_bytes()).unwrap();
        assert_eq!(t.all("package")[0].attrs, p.attrs);
    }

    #[test]
    fn typed_values() {
        // <s n=INT 42 h=INT_HEX 0xff l=LONG_HEX b=TRUE x=BYTES_HEX/>
        let mut b = b"ABX\0".to_vec();
        b.extend([0x32, 0xff, 0xff, 0, 1, b's']);
        b.extend([0x6f, 0xff, 0xff, 0, 1, b'n', 0, 0, 0, 42]);
        b.extend([0x7f, 0xff, 0xff, 0, 1, b'h', 0, 0, 0, 0xff]);
        b.extend([0x9f, 0xff, 0xff, 0, 1, b'l', 0, 0, 0x01, 0x8d, 0x0a, 0x1b, 0x2c, 0x3d]);
        b.extend([0xcf, 0xff, 0xff, 0, 1, b'b']);
        b.extend([0x4f, 0xff, 0xff, 0, 1, b'x', 0, 2, 0xde, 0xad]);
        b.extend([0x5f, 0xff, 0xff, 0, 1, b'y', 0, 2, 0xde, 0xad]);
        b.extend([0x33, 0, 0]);
        let s = &parse(&b).unwrap().children[0];
        assert_eq!(s.attr("n"), Some("42"));
        assert_eq!(s.attr("h"), Some("ff"));
        assert_eq!(s.attr("l"), Some("18d0a1b2c3d"));
        assert_eq!(s.attr("b"), Some("true"));
        assert_eq!(s.attr("x"), Some("dead"));
        assert_eq!(s.attr("y"), Some("3q0="));
    }
}
