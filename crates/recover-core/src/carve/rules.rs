use crate::error::{RecoverError, Result};
use crate::models::{CarveRule, FileFamily};
use serde::{Deserialize, Serialize};
use std::path::Path;

const EMBEDDED_SIGNATURES_JSON: &str =
    include_str!("../../../../signatures/signatures.v1.json");

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignatureFileJson {
    pub version: String,
    pub rules: Vec<SignatureRuleJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignatureRuleJson {
    pub sig_id: String,
    pub family: String,
    pub mime: String,
    pub ext: String,
    pub header_hex: String,
    pub header_offset: usize,
    pub footer_hex: Option<String>,
    pub min_len: u64,
    pub max_len: u64,
    pub validator_ref: String,
}

#[derive(Debug, Clone)]
pub struct SignatureDatabase {
    pub version: String,
    pub rules: Vec<CarveRule>,
    /// Lookup index: `first_byte_table[b]` lists indices in `rules` whose `header[0] == b`.
    first_byte_table: [Vec<usize>; 256],
}

impl SignatureDatabase {
    pub fn load_default() -> Result<Self> {
        Self::from_json_str(EMBEDDED_SIGNATURES_JSON)
    }

    pub fn load_from_path(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path).map_err(|e| RecoverError::Io {
            offset: 0,
            source: e,
        })?;
        Self::from_json_str(&raw)
    }

    pub fn from_json_str(raw: &str) -> Result<Self> {
        let parsed: SignatureFileJson = serde_json::from_str(raw)
            .map_err(|e| RecoverError::InvalidSignature(format!("Malformed JSON: {e}")))?;
        let mut rules = Vec::with_capacity(parsed.rules.len());
        for r in parsed.rules {
            let header = hex::decode(&r.header_hex).map_err(|e| {
                RecoverError::InvalidSignature(format!("Invalid header_hex in {}: {e}", r.sig_id))
            })?;
            if header.is_empty() {
                return Err(RecoverError::InvalidSignature(format!(
                    "Empty header in {}",
                    r.sig_id
                )));
            }
            let footer = match r.footer_hex {
                Some(ref h) if !h.is_empty() => Some(hex::decode(h).map_err(|e| {
                    RecoverError::InvalidSignature(format!(
                        "Invalid footer_hex in {}: {e}",
                        r.sig_id
                    ))
                })?),
                _ => None,
            };
            let family = match r.family.as_str() {
                "image" => FileFamily::Image,
                "video" => FileFamily::Video,
                "document" => FileFamily::Document,
                "archive" => FileFamily::Archive,
                _ => FileFamily::Media,
            };
            rules.push(CarveRule {
                sig_id: r.sig_id,
                family,
                header,
                header_offset: r.header_offset,
                footer,
                min_len: r.min_len,
                max_len: r.max_len,
                validator_ref: r.validator_ref,
                mime: r.mime,
                ext: r.ext,
            });
        }
        Ok(Self::from_rules(parsed.version, rules))
    }

    pub fn from_rules(version: String, rules: Vec<CarveRule>) -> Self {
        let mut first_byte_table: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
        for (idx, rule) in rules.iter().enumerate() {
            if let Some(&b0) = rule.header.first() {
                first_byte_table[b0 as usize].push(idx);
            }
        }
        Self {
            version,
            rules,
            first_byte_table,
        }
    }

    /// Filters active rules by requested extensions/types (`["jpg", "png", "docx", ...]`).
    /// Empty filter keeps all rules.
    pub fn filtered(&self, types: &[String]) -> Self {
        if types.is_empty() {
            return self.clone();
        }
        let wanted: Vec<String> = types
            .iter()
            .map(|t| t.trim().trim_start_matches('.').to_ascii_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        if wanted.is_empty() {
            return self.clone();
        }
        let kept: Vec<CarveRule> = self
            .rules
            .iter()
            .filter(|r| {
                let ext = r.ext.to_ascii_lowercase();
                if wanted.iter().any(|w| w == &ext || (w == "jpeg" && ext == "jpg")) {
                    return true;
                }
                // `bmff` validator dynamically produces heic, mp4, mov
                if r.validator_ref == "bmff"
                    && wanted
                        .iter()
                        .any(|w| matches!(w.as_str(), "heic" | "heif" | "mp4" | "mov"))
                {
                    return true;
                }
                // `zip_ooxml` validator dynamically produces docx, xlsx, zip
                if r.validator_ref == "zip_ooxml"
                    && wanted
                        .iter()
                        .any(|w| matches!(w.as_str(), "docx" | "xlsx" | "pptx" | "zip"))
                {
                    return true;
                }
                false
            })
            .cloned()
            .collect();
        Self::from_rules(self.version.clone(), kept)
    }

    #[inline]
    pub fn rules_for_first_byte(&self, b: u8) -> &[usize] {
        &self.first_byte_table[b as usize]
    }
}
