//! MAC vendor lookup from the embedded IEEE registry (MA-L, MA-M and MA-S prefixes).
//! Regenerate data/ieee-oui.tsv with scripts/ieee-oui.py.

use std::collections::HashMap;
use std::sync::OnceLock;

static MAC_PREFIXES: &str = include_str!("../data/ieee-oui.tsv");

fn table() -> &'static HashMap<&'static str, &'static str> {
    static CELL: OnceLock<HashMap<&'static str, &'static str>> = OnceLock::new();
    CELL.get_or_init(|| {
        MAC_PREFIXES
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once('\t'))
            .collect()
    })
}

pub fn vendor(mac: &str) -> Option<String> {
    let hex: String = mac.chars().filter(char::is_ascii_hexdigit).collect::<String>().to_uppercase();
    let first = u8::from_str_radix(hex.get(..2)?, 16).ok()?;
    if first & 0x02 != 0 {
        // Locally administered: typically a randomized MAC (phones, laptops with privacy on).
        return Some("Randomized/locally administered".to_string());
    }
    [9, 7, 6].iter().find_map(|&n| table().get(hex.get(..n)?).map(|v| v.to_string()))
}
