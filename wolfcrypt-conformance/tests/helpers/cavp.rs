use std::collections::HashMap;

/// A single test case from a CAVP/SHAVS file.
pub struct CavpTestCase {
    pub section: String,
    pub fields: HashMap<String, String>,
}

impl CavpTestCase {
    /// Get a field as decoded hex bytes. Panics if missing or invalid hex.
    pub fn bytes(&self, field: &str) -> Vec<u8> {
        let hex_str = self.fields.get(field).unwrap_or_else(|| {
            panic!(
                "Missing field '{}' in CAVP test case (section: {})",
                field, self.section
            )
        });
        hex::decode(hex_str).unwrap_or_else(|e| {
            panic!(
                "Invalid hex for field '{}': '{}': {} (section: {})",
                field, hex_str, e, self.section
            )
        })
    }

    /// Get a field as a usize.
    pub fn usize_field(&self, field: &str) -> usize {
        self.fields
            .get(field)
            .unwrap_or_else(|| {
                panic!(
                    "Missing field '{}' in CAVP test case (section: {})",
                    field, self.section
                )
            })
            .parse()
            .unwrap_or_else(|e| {
                panic!(
                    "Invalid integer for '{}': {} (section: {})",
                    field, e, self.section
                )
            })
    }

    /// Get a field as a raw string reference.
    pub fn string_field(&self, field: &str) -> &str {
        self.fields.get(field).unwrap_or_else(|| {
            panic!(
                "Missing field '{}' in CAVP test case (section: {})",
                field, self.section
            )
        })
    }

    /// Check if a field exists.
    pub fn has_field(&self, field: &str) -> bool {
        self.fields.contains_key(field)
    }
}

/// Parse a CAVP/SHAVS file into test cases.
/// Handles section headers `[key = value]` and key-value lines `Key = hex`.
/// Blank lines separate test cases.
pub fn parse_cavp(contents: &str) -> Vec<CavpTestCase> {
    let mut cases = Vec::new();
    let mut current_section = String::new();
    let mut current_fields: HashMap<String, String> = HashMap::new();

    for line in contents.lines() {
        let line = line.trim();

        // Skip comments
        if line.starts_with('#') {
            continue;
        }

        // Blank line: emit current case if non-empty
        if line.is_empty() {
            if !current_fields.is_empty() {
                cases.push(CavpTestCase {
                    section: current_section.clone(),
                    fields: std::mem::take(&mut current_fields),
                });
            }
            continue;
        }

        // Section header
        if line.starts_with('[') && line.ends_with(']') {
            // Emit any pending case before section change
            if !current_fields.is_empty() {
                cases.push(CavpTestCase {
                    section: current_section.clone(),
                    fields: std::mem::take(&mut current_fields),
                });
            }
            current_section = line.to_string();
            continue;
        }

        // Key = Value
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim().to_string();
            let value = value.trim().to_string();
            current_fields.insert(key, value);
        }
    }

    // Don't forget the last test case
    if !current_fields.is_empty() {
        cases.push(CavpTestCase {
            section: current_section,
            fields: current_fields,
        });
    }

    assert!(
        !cases.is_empty(),
        "CAVP file contained zero test cases"
    );
    cases
}
