//! JA4T, the TCP SYN fingerprint (FoxIO License 1.1): window size, the
//! option kinds in the order sent, MSS and window scale, as
//! `64240_2-1-3-1-1-4_1460_8`. FoxIO publishes values, not a text spec; the
//! shape here follows the published values, including `00` for a part the
//! SYN did not carry (`5744_2_1436_00`).

/// From the TCP header, starting at the source port. `None` when truncated.
pub fn ja4t(tcp: &[u8]) -> Option<String> {
    if tcp.len() < 20 {
        return None;
    }
    let doff = ((tcp[12] >> 4) as usize) * 4;
    if doff < 20 || tcp.len() < doff {
        return None;
    }
    let window = u16::from_be_bytes([tcp[14], tcp[15]]);
    let opts = &tcp[20..doff];
    let mut kinds: Vec<String> = Vec::with_capacity(8);
    let mut mss: Option<u16> = None;
    let mut scale: Option<u8> = None;
    let mut i = 0;
    while i < opts.len() {
        let kind = opts[i];
        kinds.push(kind.to_string());
        if kind <= 1 {
            i += 1;
            continue;
        }
        let Some(&len) = opts.get(i + 1) else { break };
        let len = len as usize;
        if len < 2 || i + len > opts.len() {
            break;
        }
        let data = &opts[i + 2..i + len];
        match (kind, data.len()) {
            (2, 2) => mss = Some(u16::from_be_bytes([data[0], data[1]])),
            (3, 1) => scale = Some(data[0]),
            _ => {}
        }
        i += len;
    }
    let kinds = if kinds.is_empty() {
        "00".to_string()
    } else {
        kinds.join("-")
    };
    Some(format!(
        "{window}_{kinds}_{}_{}",
        mss.map_or_else(|| "00".to_string(), |m| m.to_string()),
        scale.map_or_else(|| "00".to_string(), |s| s.to_string())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syn(window: u16, opts: &[u8]) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[0..2].copy_from_slice(&51234u16.to_be_bytes());
        h[2..4].copy_from_slice(&443u16.to_be_bytes());
        let doff = (20 + opts.len()).div_ceil(4);
        h[12] = (doff as u8) << 4;
        h[13] = 0x02;
        h[14..16].copy_from_slice(&window.to_be_bytes());
        h.extend_from_slice(opts);
        h.resize(doff * 4, 0);
        h
    }

    #[test]
    fn linux_and_windows_shapes() {
        // Linux: MSS, SACK permitted, timestamps, NOP, window scale 7.
        let linux = syn(
            65535,
            &[
                2, 4, 5, 180, 4, 2, 8, 10, 0, 0, 0, 0, 0, 0, 0, 0, 1, 3, 3, 7,
            ],
        );
        assert_eq!(ja4t(&linux).unwrap(), "65535_2-4-8-1-3_1460_7");
        // Windows: MSS, NOP, window scale 8, NOP, NOP, SACK permitted.
        let windows = syn(64240, &[2, 4, 5, 180, 1, 3, 3, 8, 1, 1, 4, 2]);
        assert_eq!(ja4t(&windows).unwrap(), "64240_2-1-3-1-1-4_1460_8");
    }

    #[test]
    fn absent_parts_are_00() {
        assert_eq!(ja4t(&syn(5744, &[2, 4, 5, 156])).unwrap(), "5744_2_1436_00");
        assert_eq!(ja4t(&syn(1024, &[])).unwrap(), "1024_00_00_00");
        assert_eq!(ja4t(&[0u8; 19]), None);
    }
}
