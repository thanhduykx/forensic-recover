use crate::error::{RecoverError, Result};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

/// A decoded SQLite column value.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Int(i64),
    Float(f64),
    Blob(Vec<u8>),
    Text(String),
}

impl SqlValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            SqlValue::Text(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            SqlValue::Int(v) => Some(*v),
            _ => None,
        }
    }
}

/// Pure-Rust, zero-C, strictly read-only SQLite 3 database reader.
/// Parses `sqlite_schema` (root page 1) and traverses Table B-Trees (`0x05` / `0x0D`).
pub struct ReadOnlySqlite {
    data: Vec<u8>,
    page_size: usize,
}

impl ReadOnlySqlite {
    pub fn open(path: &Path) -> Result<Self> {
        let mut f = File::open(path).map_err(|e| RecoverError::Io {
            offset: 0,
            source: e,
        })?;
        let mut data = Vec::new();
        f.read_to_end(&mut data).map_err(|e| RecoverError::Io {
            offset: 0,
            source: e,
        })?;
        Self::from_bytes(data)
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        if data.len() < 100 || &data[..16] != b"SQLite format 3\0" {
            return Err(RecoverError::Parse("Not a valid SQLite 3 database".into()));
        }
        let raw_ps = u16::from_be_bytes([data[16], data[17]]) as usize;
        let page_size = if raw_ps == 1 { 65_536 } else { raw_ps };
        if !page_size.is_power_of_two() || page_size < 512 {
            return Err(RecoverError::Parse("Invalid SQLite page size".into()));
        }
        Ok(Self { data, page_size })
    }

    /// Lists `(table_name, root_page, sql)` from `sqlite_schema` (page 1).
    pub fn list_tables(&self) -> HashMap<String, (u32, String)> {
        let mut out = HashMap::new();
        for row in self.read_table_rows_by_root(1) {
            let kind = row.first().and_then(|v| v.as_str()).unwrap_or("");
            let name = row.get(1).and_then(|v| v.as_str()).unwrap_or("");
            let root = row.get(3).and_then(|v| v.as_i64()).unwrap_or(0);
            let sql = row.get(4).and_then(|v| v.as_str()).unwrap_or("");
            if kind == "table" && !name.is_empty() && root > 0 {
                out.insert(name.to_string(), (root as u32, sql.to_string()));
            }
        }
        out
    }

    /// Reads all rows from a named table.
    pub fn read_table(&self, table_name: &str) -> Vec<Vec<SqlValue>> {
        let tables = self.list_tables();
        if let Some((root_page, _)) = tables.get(table_name) {
            self.read_table_rows_by_root(*root_page)
        } else {
            Vec::new()
        }
    }

    pub fn read_table_rows_by_root(&self, root_page: u32) -> Vec<Vec<SqlValue>> {
        let mut rows = Vec::new();
        let mut stack = vec![root_page];
        let mut guard = 0usize;
        while let Some(pg) = stack.pop() {
            guard += 1;
            if guard > 50_000 || pg == 0 {
                break;
            }
            let page_start = (pg as usize - 1) * self.page_size;
            if page_start + self.page_size > self.data.len() {
                continue;
            }
            let hdr_off = if pg == 1 { 100 } else { 0 };
            let page = &self.data[page_start..page_start + self.page_size];
            if hdr_off + 8 > page.len() {
                continue;
            }
            let ptype = page[hdr_off];
            let cell_count = u16::from_be_bytes([page[hdr_off + 3], page[hdr_off + 4]]) as usize;
            let ptr_array_off = match ptype {
                0x0D => hdr_off + 8,
                0x05 => {
                    // Push right-most child page
                    if hdr_off + 12 <= page.len() {
                        let right = u32::from_be_bytes([
                            page[hdr_off + 8],
                            page[hdr_off + 9],
                            page[hdr_off + 10],
                            page[hdr_off + 11],
                        ]);
                        stack.push(right);
                    }
                    hdr_off + 12
                }
                _ => continue,
            };

            let mut ptrs = Vec::with_capacity(cell_count);
            for i in 0..cell_count {
                let p = ptr_array_off + i * 2;
                if p + 2 > page.len() {
                    break;
                }
                ptrs.push(u16::from_be_bytes([page[p], page[p + 1]]) as usize);
            }

            if ptype == 0x05 {
                for cell_off in ptrs.into_iter().rev() {
                    if cell_off + 4 <= page.len() {
                        let child = u32::from_be_bytes([
                            page[cell_off],
                            page[cell_off + 1],
                            page[cell_off + 2],
                            page[cell_off + 3],
                        ]);
                        stack.push(child);
                    }
                }
            } else {
                for cell_off in ptrs {
                    if cell_off >= page.len() {
                        continue;
                    }
                    if let Some(vals) = self.parse_leaf_cell(page, cell_off) {
                        rows.push(vals);
                    }
                }
            }
        }
        rows
    }

    fn parse_leaf_cell(&self, page: &[u8], cell_off: usize) -> Option<Vec<SqlValue>> {
        let (payload_len, n1) = read_varint(&page[cell_off..])?;
        let (_rowid, n2) = read_varint(&page[cell_off + n1..])?;
        let payload_start = cell_off + n1 + n2;
        let max_local = self.page_size - 35;
        let payload_bytes = if (payload_len as usize) <= max_local && payload_start + (payload_len as usize) <= page.len() {
            &page[payload_start..payload_start + (payload_len as usize)]
        } else {
            let avail = page.len().saturating_sub(payload_start);
            &page[payload_start..payload_start + avail]
        };
        parse_sqlite_record(payload_bytes)
    }
}

fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut val = 0u64;
    for (i, &b) in buf.iter().enumerate().take(9.min(buf.len())) {
        if i == 8 {
            val = (val << 8) | (b as u64);
            return Some((val, 9));
        }
        val = (val << 7) | ((b & 0x7F) as u64);
        if (b & 0x80) == 0 {
            return Some((val, i + 1));
        }
    }
    None
}

fn parse_sqlite_record(rec: &[u8]) -> Option<Vec<SqlValue>> {
    let (hdr_len, first_n) = read_varint(rec)?;
    let hdr_len = hdr_len as usize;
    if hdr_len < first_n || hdr_len > rec.len() {
        return None;
    }
    let mut serial_types = Vec::new();
    let mut pos = first_n;
    while pos < hdr_len {
        let (st, n) = read_varint(&rec[pos..])?;
        serial_types.push(st);
        pos += n;
    }

    let mut values = Vec::with_capacity(serial_types.len());
    let mut body_pos = hdr_len;
    for st in serial_types {
        match st {
            0 => values.push(SqlValue::Null),
            1 => {
                let v = *rec.get(body_pos)? as i8 as i64;
                body_pos += 1;
                values.push(SqlValue::Int(v));
            }
            2 => {
                let b = rec.get(body_pos..body_pos + 2)?;
                body_pos += 2;
                values.push(SqlValue::Int(i16::from_be_bytes([b[0], b[1]]) as i64));
            }
            3 => {
                let b = rec.get(body_pos..body_pos + 3)?;
                body_pos += 3;
                let sign = if (b[0] & 0x80) != 0 { 0xFF } else { 0x00 };
                values.push(SqlValue::Int(
                    i32::from_be_bytes([sign, b[0], b[1], b[2]]) as i64,
                ));
            }
            4 => {
                let b = rec.get(body_pos..body_pos + 4)?;
                body_pos += 4;
                values.push(SqlValue::Int(i32::from_be_bytes([b[0], b[1], b[2], b[3]]) as i64));
            }
            5 => {
                let b = rec.get(body_pos..body_pos + 6)?;
                body_pos += 6;
                let sign = if (b[0] & 0x80) != 0 { 0xFF } else { 0x00 };
                values.push(SqlValue::Int(i64::from_be_bytes([
                    sign, sign, b[0], b[1], b[2], b[3], b[4], b[5],
                ])));
            }
            6 => {
                let b = rec.get(body_pos..body_pos + 8)?;
                body_pos += 8;
                values.push(SqlValue::Int(i64::from_be_bytes(b.try_into().ok()?)));
            }
            7 => {
                let b = rec.get(body_pos..body_pos + 8)?;
                body_pos += 8;
                values.push(SqlValue::Float(f64::from_be_bytes(b.try_into().ok()?)));
            }
            8 => values.push(SqlValue::Int(0)),
            9 => values.push(SqlValue::Int(1)),
            10 | 11 => values.push(SqlValue::Null),
            n if n >= 12 && n % 2 == 0 => {
                let len = ((n - 12) / 2) as usize;
                let end = (body_pos + len).min(rec.len());
                values.push(SqlValue::Blob(rec[body_pos..end].to_vec()));
                body_pos = end;
            }
            n if n >= 13 && n % 2 == 1 => {
                let len = ((n - 13) / 2) as usize;
                let end = (body_pos + len).min(rec.len());
                values.push(SqlValue::Text(
                    String::from_utf8_lossy(&rec[body_pos..end]).to_string(),
                ));
                body_pos = end;
            }
            _ => values.push(SqlValue::Null),
        }
    }
    Some(values)
}
