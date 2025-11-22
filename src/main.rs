use clap::Parser;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
// Target: "BunnyName123"
const SIG_ASCII: &str = "42756e6e794e616d65313233";
// Target: "B.u.n.n.y.N.a.m.e.1.2.3" (Wide Char)
const SIG_WIDE: &str  = "420075006e006e0079004e0061006d0065003100320033";
const TARGET_IP: &str = "192.168.1.50";                    // Replace with target
const LOG_FILENAME: &str = "captured_traffic.txt";
// =================================================
#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    interface: Option<String>,
}

fn resolve_tshark_path() -> String {
    let common_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        r"C:\Wireshark\tshark.exe",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
    ];
    if Command::new("tshark").arg("-v").stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok() {
        return "tshark".to_string();
    }
    for path in common_paths {
        if Path::new(path).exists() { return path.to_string(); }
    }
    "tshark".to_string()
}

fn choose_interface(tshark_path: &str) -> String {
    println!("[*] Querying interfaces...");
    let output = match Command::new(tshark_path).arg("-D").output() {
        Ok(o) => o,
        Err(_) => panic!("Could not run tshark."),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{}", stdout);

    loop {
        print!("Select interface number (e.g. 1): ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let trimmed = input.trim();
            if !trimmed.is_empty() { return trimmed.to_string(); }
        }
    }
}

fn main() {
    let args = Args::parse();
    let tshark_binary = resolve_tshark_path();

    let interface = match args.interface {
        Some(i) => i,
        None => choose_interface(&tshark_binary),
    };

    // Prepare Output File (Truncate/Overwrite on start)
    let mut log_file = File::create(LOG_FILENAME).expect("Failed to create log file");

    println!("=================================================");
    println!("ACTIVE MONITORING");
    println!("Filter IP:   {}", TARGET_IP);
    println!("Logging to:  {}", LOG_FILENAME);
    println!("Mode:        ASCII ONLY OUTPUT");
    println!("Interface:   {}", interface);
    println!("=================================================");

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        println!("\nStopping...");
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C");

    // -l: Line buffering (Critical)
    // -x: Hex and ASCII dump within tshark output
    // -n: No DNS
    // -Y: Display Filter
    let mut child = Command::new(&tshark_binary)
        .args([
            "-i", &interface,
            "-l", "-n", "-x",
            "-Y", &format!("ip.dst == {} || ip.src == {}", TARGET_IP, TARGET_IP) // Monitor both ways usually
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to start tshark");

    let stdout = child.stdout.take().expect("Failed to capture stdout");
    let reader = BufReader::new(stdout);

    let mut raw_packet_lines: Vec<String> = Vec::new();
    let mut searchable_hex = String::new();
    let mut packet_count = 0u64;
    let mut total_bytes_written = 0usize;

    for line in reader.lines() {
        if !running.load(Ordering::SeqCst) { break; }

        if let Ok(text) = line {
            let trimmed = text.trim();

            // TShark -x output separates packets with empty lines or "Frame X"
            if trimmed.is_empty() || text.starts_with("Frame ") {
                if !raw_packet_lines.is_empty() {
                    process_packet(
                        &mut packet_count,
                        &raw_packet_lines,
                        &searchable_hex,
                        &mut log_file,
                        &mut total_bytes_written
                    );
                    raw_packet_lines.clear();
                    searchable_hex.clear();
                }
            }

            // Always buffer the raw line for the file
            if !trimmed.is_empty() {
                raw_packet_lines.push(text.clone());

                // If line looks like hex dump, extract hex for searching
                if is_hex_dump_line(&text) {
                    searchable_hex.push_str(&extract_hex_bytes(&text));
                }
            }
        }
    }

    let _ = child.kill();
    println!("\n[Done] Total packets captured: {}. Check {} for details.", packet_count, LOG_FILENAME);
}

fn process_packet(
    count: &mut u64,
    lines: &Vec<String>, // Kept for size calculation, but ignored for writing
    clean_hex: &str,
    file: &mut File,
    bytes_counter: &mut usize
) {
    *count += 1;

    // 1. CONVERT HEX TO CLEAN ASCII
    let ascii_content = hex_to_clean_ascii(clean_hex);

    // 2. WRITE ONLY ASCII TO FILE
    // We filter out packets that resulted in empty strings (no printable data)
    // unless you want to see empty newlines for packets with only headers.
    if !ascii_content.is_empty() {
        let _ = file.write_all(ascii_content.as_bytes());
        let _ = file.write_all(b"\n"); // Separator between packets
        let _ = file.flush();
    }

    // Update stats
    // Using lines.len() essentially counts the raw input size from TShark roughly
    *bytes_counter += lines.iter().map(|s| s.len()).sum::<usize>();
    print!("\rProcessed Packets: {} | Bytes Processed: ~{} KB", count, *bytes_counter / 1024);
    io::stdout().flush().unwrap();

    // 3. CHECK FOR KEYWORDS (Alert to console only)
    let found_ascii = clean_hex.contains(SIG_ASCII);
    let found_wide = clean_hex.contains(SIG_WIDE);

    if found_ascii || found_wide {
        println!("\n\n[!!!] TARGET FOUND in Packet #{}", count);
        if found_ascii { println!("      -> Matched ASCII: bunnyname"); }
        if found_wide  { println!("      -> Matched WIDE:  bunnyname"); }
        println!("      (Content saved to log file)\n");

        // Note: We do NOT write the "LOG_NOTE" to the file anymore
        // to ensure the file remains pure ASCII data.
    }
}

// Logic to parse TShark -x output
fn is_hex_dump_line(line: &str) -> bool {
    if line.len() < 6 { return false; }
    let start = &line[..4];
    if !start.chars().all(|c| c.is_ascii_hexdigit()) { return false; }
    if !line.chars().nth(4).unwrap().is_whitespace() { return false; }
    true
}

fn extract_hex_bytes(line: &str) -> String {
    let mut hex_string = String::new();
    // TShark hex usually lies between char 6 and 54
    let end_idx = if line.len() > 54 { 54 } else { line.len() };
    let start_idx = if line.len() > 6 { 6 } else { 0 };

    if start_idx >= end_idx { return String::new(); }

    let sub = &line[start_idx..end_idx];
    for c in sub.chars() {
        if c.is_ascii_hexdigit() {
            hex_string.push(c.to_ascii_lowercase());
        }
    }
    hex_string
}

// Convert hex string "5265..." to ASCII "Re..."
// Replaces non-printable characters with '.'
fn hex_to_clean_ascii(hex_str: &str) -> String {
    let mut ascii = String::with_capacity(hex_str.len() / 2);
    let chars: Vec<char> = hex_str.chars().collect();

    for chunk in chars.chunks(2) {
        if chunk.len() == 2 {
            let s: String = chunk.iter().collect();
            if let Ok(byte) = u8::from_str_radix(&s, 16) {
                // Allow standard printable ASCII (32-126)
                if byte >= 32 && byte <= 126 {
                    ascii.push(byte as char);
                } else {
                    ascii.push('.');
                }
            }
        }
    }
    ascii
}