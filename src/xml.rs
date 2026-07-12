//! Unified XML element tree built from either binary AXML (axmldecoder) or
//! plaintext XML (roxmltree). Attributes in the Android namespace are stored
//! under the `android:<local>` key, mirroring how pyaxmlparser renders them.

use std::collections::HashMap;

pub const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

#[derive(Debug, Clone, Default)]
pub struct Element {
    pub tag: String,
    pub attrs: HashMap<String, String>,
    pub text: String,
    pub children: Vec<Element>,
}

impl Element {
    /// Raw attribute lookup by exact key.
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs.get(key).map(|s| s.as_str())
    }

    /// Android-namespaced attribute; falls back to the bare local name.
    pub fn android(&self, name: &str) -> Option<&str> {
        let ns_key = format!("android:{name}");
        self.attrs
            .get(&ns_key)
            .or_else(|| self.attrs.get(name))
            .map(|s| s.as_str())
    }

    pub fn android_bool(&self, name: &str) -> Option<bool> {
        self.android(name).map(|v| v.eq_ignore_ascii_case("true"))
    }

    /// First direct child with the given tag (like ElementTree.find).
    pub fn find(&self, tag: &str) -> Option<&Element> {
        self.children.iter().find(|c| c.tag == tag)
    }

    /// All descendants-or-self matching the tag (like ElementTree.iter).
    pub fn iter<'a>(&'a self, tag: &str) -> Vec<&'a Element> {
        let mut out = Vec::new();
        self.collect_iter(tag, &mut out);
        out
    }

    fn collect_iter<'a>(&'a self, tag: &str, out: &mut Vec<&'a Element>) {
        if self.tag == tag {
            out.push(self);
        }
        for c in &self.children {
            c.collect_iter(tag, out);
        }
    }
}

/// Parse a manifest/compiled-xml blob: binary AXML first, plaintext fallback.
pub fn parse_axml_or_xml(raw: &[u8]) -> Option<Element> {
    if let Some(el) = parse_axml(raw) {
        return Some(el);
    }
    parse_text_xml(raw)
}

fn parse_axml(raw: &[u8]) -> Option<Element> {
    let doc = axmldecoder::parse(raw).ok()?;
    match doc.get_root() {
        Some(axmldecoder::Node::Element(e)) => Some(from_axml(e)),
        _ => None,
    }
}

fn from_axml(e: &axmldecoder::Element) -> Element {
    let mut attrs = HashMap::new();
    for (k, v) in e.get_attributes() {
        attrs.insert(k.clone(), v.clone());
    }
    let mut children = Vec::new();
    let mut text = String::new();
    for child in e.get_children() {
        match child {
            axmldecoder::Node::Element(ce) => children.push(from_axml(ce)),
            axmldecoder::Node::Cdata(cd) => {
                if !text.is_empty() {
                    text.push('\n');
                }
                text.push_str(cd.get_data());
            }
        }
    }
    Element {
        tag: e.get_tag().to_string(),
        attrs,
        text: text.trim().to_string(),
        children,
    }
}

fn parse_text_xml(raw: &[u8]) -> Option<Element> {
    let s = String::from_utf8_lossy(raw);
    let doc = roxmltree::Document::parse(&s).ok()?;
    Some(from_rox(doc.root_element()))
}

fn from_rox(node: roxmltree::Node) -> Element {
    let mut attrs = HashMap::new();
    for a in node.attributes() {
        let key = match a.namespace() {
            Some(ns) if ns == ANDROID_NS => format!("android:{}", a.name()),
            _ => a.name().to_string(),
        };
        attrs.insert(key, a.value().to_string());
    }
    let mut text = String::new();
    let mut children = Vec::new();
    for child in node.children() {
        if child.is_element() {
            children.push(from_rox(child));
        } else if child.is_text() {
            if let Some(t) = child.text() {
                let t = t.trim();
                if !t.is_empty() {
                    if !text.is_empty() {
                        text.push('\n');
                    }
                    text.push_str(t);
                }
            }
        }
    }
    Element {
        tag: node.tag_name().name().to_string(),
        attrs,
        text,
        children,
    }
}
