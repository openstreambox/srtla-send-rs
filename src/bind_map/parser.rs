//! Parsing: bytes in, validated header + typed values out (ADR-003 §1).
//!
//! Nothing constructed here can hold a value the ADR forbids — the constructors
//! are the only way in, and they *parse* rather than validate, so downstream
//! code never re-checks a [`LinkId`] or an [`IfaceName`].
//!
//! Sidecar rows deliberately stay **raw** until [`super::coherence`] runs them.
//! Row validation must happen *after* the hash-coherence check (ADR-003 §4.1),
//! and this module has never seen the IP file, so it cannot perform that check;
//! validating rows early would report a row bug for content already known to be
//! stale.

use std::net::IpAddr;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::error::BindMapError;
use crate::sender::{normalise_link_weights, parse_ip_line};

/// The sidecar `schema_version` this build reads and writes.
pub const BIND_MAP_SCHEMA_VERSION: u32 = 1;

/// Length of a lowercase-hex SHA-256 digest.
const SHA256_HEX_LEN: usize = 64;

/// Maximum `link_id` length in bytes.
const LINK_ID_MAX_LEN: usize = 64;
/// Maximum interface-name length in bytes (`IFNAMSIZ - 1`).
const IFACE_MAX_LEN: usize = 15;
/// Maximum `id_path` length in bytes.
const ID_PATH_MAX_LEN: usize = 4096;

/// True for printable, non-space ASCII (`0x21`–`0x7E`).
fn is_printable_ascii(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// An opaque, writer-assigned link identity.
///
/// Stable across reloads, reconnects, IP changes, and interface renames. The
/// sender never parses meaning out of it and never invents one.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LinkId(String);

impl LinkId {
    /// Parse a writer-supplied identity, rejecting anything outside the domain.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.len() > LINK_ID_MAX_LEN {
            return Err(format!(
                "{} bytes exceeds the {LINK_ID_MAX_LEN}-byte ceiling",
                raw.len()
            ));
        }
        if !is_printable_ascii(raw) {
            return Err("must be 1-64 printable ASCII bytes with no spaces".to_string());
        }
        Ok(Self(raw.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated network-interface name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IfaceName(String);

impl IfaceName {
    /// Parse an interface name against the kernel's own naming rules.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.len() > IFACE_MAX_LEN {
            return Err(format!(
                "{} bytes exceeds the {IFACE_MAX_LEN}-byte kernel ceiling",
                raw.len()
            ));
        }
        if !is_printable_ascii(raw) {
            return Err("must be 1-15 printable ASCII bytes with no spaces".to_string());
        }
        if raw.contains('/') || raw == "." || raw == ".." {
            return Err("must not be a path component".to_string());
        }
        Ok(Self(raw.to_string()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One validated sidecar row: an identity, its current socket key, and optional
/// writer provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMapRow {
    pub link_id: LinkId,
    pub ip: IpAddr,
    pub iface: IfaceName,
    /// Normalised weight from the corresponding IP-file entry, never the sidecar.
    pub weight: u8,
    /// Opaque writer provenance. Never opened, stat-ed, or resolved.
    pub id_path: Option<String>,
}

/// Parse the optional `id_path` provenance field.
pub(super) fn parse_id_path(raw: &str) -> Result<String, String> {
    if raw.len() > ID_PATH_MAX_LEN {
        return Err(format!(
            "{} bytes exceeds the {ID_PATH_MAX_LEN}-byte ceiling",
            raw.len()
        ));
    }
    if !raw.starts_with('/') {
        return Err("must be an absolute path".to_string());
    }
    Ok(raw.to_string())
}

/// A coherent, fully validated mapping — the thing the sender may act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedPool {
    pub generation: u64,
    pub ips_file_sha256: String,
    pub rows: Vec<BindMapRow>,
}

/// The `BIND_IPS_FILE`, read once: its raw-byte digest and the IPs the legacy
/// rules accept from it.
///
/// Hashing and parsing share one read on purpose — reading twice would let the
/// file change in between and produce a digest describing content the sender did
/// not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpsFile {
    sha256: String,
    accepted: Vec<IpAddr>,
    weights: Vec<u8>,
}

impl IpsFile {
    /// Parse and hash one read of the IP list.
    ///
    /// Uses the sender's shared `parse_ip_line` and `normalise_link_weights`:
    /// skip blank or invalid lines; preserve valid IPs with a bad weight as 1.
    /// Duplicates are preserved,
    /// because position is what disambiguates them (ADR-003 §2).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BindMapError> {
        let text = std::str::from_utf8(bytes).map_err(|e| BindMapError::Unreadable {
            path: "<ips file>".to_string(),
            detail: format!("not valid UTF-8: {e}"),
        })?;

        let (accepted, mut weights): (Vec<_>, Vec<_>) = text
            .lines()
            .enumerate()
            .filter_map(|(index, line)| parse_ip_line(line.trim(), index + 1))
            .unzip();
        normalise_link_weights(&mut weights);

        Ok(Self {
            sha256: hex_digest(bytes),
            accepted,
            weights,
        })
    }

    /// Lowercase hex SHA-256 over the raw bytes that were read.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// The accepted IPs, in file order, duplicates preserved.
    #[must_use]
    pub fn accepted(&self) -> &[IpAddr] {
        &self.accepted
    }

    /// Normalised weights in accepted-entry order, including duplicate IPs.
    #[must_use]
    pub fn weights(&self) -> &[u8] {
        &self.weights
    }
}

/// Lowercase hex SHA-256 of `bytes`.
fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A parsed sidecar with a validated header and still-raw rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMapDoc {
    pub generation: u64,
    pub ips_file_sha256: String,
    pub(super) links: Vec<RawRow>,
    pub(super) explicit_links: bool,
}

impl BindMapDoc {
    /// Rows exactly as the writer published them, unvalidated.
    pub(super) fn raw_links(&self) -> &[RawRow] {
        &self.links
    }
}

/// One row before its fields have been parsed into typed values.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(super) struct RawRow {
    pub(super) link_id: String,
    pub(super) ip: String,
    pub(super) iface: String,
    #[serde(default)]
    pub(super) id_path: Option<String>,
}

/// The wire shape. Unknown keys are ignored so an additive field within the same
/// `schema_version` cannot break an older reader (ADR-003 §1.1).
#[derive(Deserialize)]
struct WireDoc {
    schema_version: u32,
    generation: u64,
    ips_file_sha256: String,
    #[serde(default, deserialize_with = "explicit_rows")]
    links: Option<Vec<RawRow>>,
}

fn explicit_rows<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Vec<RawRow>>, D::Error> {
    Vec::deserialize(d).map(Some)
}

/// Parse a sidecar document and validate its header.
///
/// Checks run in the ADR's declared order — version, then generation, then
/// digest form — so the reported reason is reproducible.
pub fn parse_sidecar(bytes: &[u8]) -> Result<BindMapDoc, BindMapError> {
    let wire: WireDoc =
        serde_json::from_slice(bytes).map_err(|e| BindMapError::MalformedJson(e.to_string()))?;

    if wire.schema_version != BIND_MAP_SCHEMA_VERSION {
        return Err(BindMapError::UnsupportedSchemaVersion {
            found: wire.schema_version,
        });
    }

    if wire.generation == 0 {
        return Err(BindMapError::InvalidHeader {
            field: "generation",
            detail: "0 is the reserved unset sentinel; the floor is 1".to_string(),
        });
    }

    if wire.ips_file_sha256.len() != SHA256_HEX_LEN
        || !wire
            .ips_file_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BindMapError::InvalidHeader {
            field: "ips_file_sha256",
            detail: format!(
                "must be {SHA256_HEX_LEN} lowercase hex characters, got `{}`",
                wire.ips_file_sha256
            ),
        });
    }

    Ok(BindMapDoc {
        generation: wire.generation,
        ips_file_sha256: wire.ips_file_sha256,
        explicit_links: wire.links.is_some(),
        links: wire.links.unwrap_or_default(),
    })
}
