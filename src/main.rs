use std::{env, error::Error, collections::BinaryHeap, cmp::Reverse};

use chrono::{TimeZone, Timelike, Utc};
use etherparse::{SlicedPacket, InternetSlice, TransportSlice};
use pcap::Capture;

const MAX_DELAY_NS: u64 = 3_000_000_000; // 3 seconds in nanoseconds

/// Parse a B6034 payload into (accept_time_ns, formatted_body).
fn parse_quote(payload: &[u8]) -> Option<(u64, String)> {
    if payload.len() < 214 { return None; }

    // Quote‐accept time: ASCII HHMMSSuu at bytes [206..214)
    let accept_raw = std::str::from_utf8(&payload[206..214]).ok()?;
    let h:  u64 = accept_raw[0..2].parse().ok()?;
    let m:  u64 = accept_raw[2..4].parse().ok()?;
    let s:  u64 = accept_raw[4..6].parse().ok()?;
    let uu: u64 = accept_raw[6..8].parse().ok()?;
    let accept_ns = h * 3_600_000_000_000
                  + m *   60_000_000_000
                  + s *    1_000_000_000
                  + uu *        100_000;

    // ISIN code at [5..17)
    let issue = std::str::from_utf8(&payload[5..17]).ok()?
        .trim().to_string();

    // Bids: five (5+7) pairs starting at byte 29
    let mut idx = 29;
    let mut bids = Vec::with_capacity(5);
    for _ in 0..5 {
        let price = std::str::from_utf8(&payload[idx..idx+5]).ok()?.to_string();
        idx += 5;
        let qty   = std::str::from_utf8(&payload[idx..idx+7]).ok()?.to_string();
        idx += 7;
        bids.push((qty, price));
    }

    // Skip total‐ask‐volume (7 bytes)
    idx += 7;

    // Asks: five (5+7) pairs
    let mut asks = Vec::with_capacity(5);
    for _ in 0..5 {
        let price = std::str::from_utf8(&payload[idx..idx+5]).ok()?.to_string();
        idx += 5;
        let qty   = std::str::from_utf8(&payload[idx..idx+7]).ok()?.to_string();
        idx += 7;
        asks.push((qty, price));
    }

    // Build the output line: accept, issue, bids (5→1), asks (1→5)
    let mut parts = vec![accept_raw.to_string(), issue];
    for (qty, price) in bids.iter().rev() {
        parts.push(format!("{}@{}", qty, price));
    }
    for (qty, price) in asks {
        parts.push(format!("{}@{}", qty, price));
    }

    Some((accept_ns, parts.join(" ")))
}

fn main() -> Result<(), Box<dyn Error>> {
    // --- Argument parsing ---
    let mut args: Vec<String> = env::args().skip(1).collect();
    let reorder = if args.get(0).map(|s| s.as_str()) == Some("-r") {
        args.remove(0);
        true
    } else {
        false
    };
    let pcap_path = args.get(0)
        .expect("Usage: parse-quote [-r] <file.pcap>");

    // --- Open the pcap file ---
    let mut cap = Capture::from_file(pcap_path)?;
    let mut heap: BinaryHeap<Reverse<(u64, String)>> = BinaryHeap::new();

    // --- Packet loop ---
    while let Ok(pkt) = cap.next() {
        let hdr = pkt.header.ts;
        let pkt_time_str = format!("{}.{}", hdr.tv_sec, format!("{:06}", hdr.tv_usec));

        // Convert tv_usec→nsec and build a DateTime to get seconds‐since‐midnight
        let nsec = (hdr.tv_usec as u32) * 1_000;
        let dt   = Utc.timestamp_opt(hdr.tv_sec as i64, nsec)
                        .single()
                        .expect("invalid timestamp");
        let t    = dt.time();
        let pkt_ns = (t.num_seconds_from_midnight() as u64) * 1_000_000_000
                   + (t.nanosecond() as u64);

        // Peel off Ethernet → IPv4 → UDP
        if let Ok(sliced) = SlicedPacket::from_ethernet(&pkt.data) {
            if let Some(InternetSlice::Ipv4(ip_hdr, _)) = sliced.ip {
                if ip_hdr.protocol() == 17 {
                    if let Some(TransportSlice::Udp(udp_hdr)) = sliced.transport {
                        let dst = udp_hdr.destination_port();
                        if dst == 15515 || dst == 15516 {
                            let payload = sliced.payload;
                            if payload.starts_with(b"B6034") {
                                if let Some((accept_ns, body)) = parse_quote(payload) {
                                    let line = format!("{} {}", pkt_time_str, body);
                                    if reorder {
                                        heap.push(Reverse((accept_ns, line)));
                                        let thresh = pkt_ns.saturating_sub(MAX_DELAY_NS);
                                        while let Some(Reverse((ts, _))) = heap.peek() {
                                            if *ts <= thresh {
                                                let Reverse((_, out)) = heap.pop().unwrap();
                                                println!("{}", out);
                                            } else {
                                                break;
                                            }
                                        }
                                    } else {
                                        println!("{}", line);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // --- Flush any remaining items if reordering ---
    if reorder {
        while let Some(Reverse((_, out))) = heap.pop() {
            println!("{}", out);
        }
    }

    Ok(())
}
