use clap::Parser;
use rtshark::RTSharkBuilder;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const TARGET_SIGNATURE: &str = r"S\sa\sn\sg\so\so\sn";

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "1")]
    interface: String,

    #[arg(short, long)]
    output: Option<String>,
}

fn resolve_tshark_path() -> String {
    let common_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        r"C:\Wireshark\tshark.exe",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
    ];

    if Command::new("tshark").arg("-v").stdout(Stdio::null()).status().is_ok() {
        return "tshark".to_string();
    }
    for path in common_paths {
        if Path::new(path).exists() {
            return path.to_string();
        }
    }
    "tshark".to_string()
}

fn main() {
    let args = Args::parse();
    // We use a physical file path instead of a pipe to avoid Windows pipe logic errors
    let capture_file = generate_temp_file_path();
    let tshark_binary = resolve_tshark_path();

    // 1. Setup Ctrl+C
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    let p_cleanup = capture_file.clone();

    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        eprintln!("\n[*] Stopping...");
        cleanup_file(&p_cleanup);
    }).expect("Error setting Ctrl-C handler");

    eprintln!("[*] Interface: {}", args.interface);
    eprintln!("[*] Cache File: {}", capture_file.display());

    // Ensure clean state
    cleanup_file(&capture_file);

    // 2. Start TShark (Producer)
    // We use -l to flush buffers, and -P to force pcapng format which works well with appending
    let mut tshark_cmd = Command::new(&tshark_binary);
    tshark_cmd
        .args(["-i", &args.interface])
        .args(["-w", &capture_file.to_string_lossy()]) // Write to file
        .arg("-l") // Flush often
        .stdout(Stdio::null());
    // .stderr(Stdio::null()); // Keep stderr visible for permissions errors

    let mut tshark_process = match tshark_cmd.spawn() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] Failed to run {}: {}", tshark_binary, e);
            return;
        }
    };

    // 3. WAIT for TShark to actually create the file
    eprint!("[*] Returning TShark init...");
    let max_retries = 100; // Wait up to 10 seconds
    let mut file_ready = false;

    for _ in 0..max_retries {
        if capture_file.exists() {
            // Check if file has size > 0 (header written)
            if let Ok(meta) = fs::metadata(&capture_file) {
                if meta.len() > 0 {
                    file_ready = true;
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(100));
        eprint!(".");
    }
    eprintln!("");

    if !file_ready {
        eprintln!("[!] Error: TShark failed to create capture file. Check permissions/interface.");
        let _ = tshark_process.kill();
        return;
    }

    // 4. Start RTShark (Consumer)
    // Now that file exists, open it.
    let builder = RTSharkBuilder::builder()
        .input_path(capture_file.to_str().unwrap());

    let mut rtshark = match builder.spawn() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[!] RTShark Init Failed: {}", e);
            let _ = tshark_process.kill();
            cleanup_file(&capture_file);
            return;
        }
    };

    eprintln!("[*] Tunnel Active. Scanning packets...");
    let mut packet_count = 0u64;

    // 5. Read Loop
    while running.load(Ordering::SeqCst) {
        // rtshark.read() will return packets until it hits EOF.
        // Since TShark is still writing, we might hit EOF intermittently.
        match rtshark.read() {
            Ok(Some(packet)) => {
                packet_count += 1;
                let packet_debug = format!("{:?}", packet);

                if packet_debug.contains(TARGET_SIGNATURE) {
                    println!("MATCH_FOUND_PACKET_{}", packet_count);
                    println!("{}", packet_debug);
                    println!("--END_MATCH--\n");
                    let _ = io::stdout().flush();

                    if let Some(ref path) = args.output {
                        save_to_file(path, packet_count, &packet_debug);
                    }
                }
            }
            Ok(None) => {
                // EOF reached? On a live file, this means we read everything written SO FAR.
                // We shouldn't break, we should wait for TShark to write more.
                // However, rtshark 0.3 might mark the stream as "Done".
                // If it stops yielding, we might need to restart the loop?
                // For now, check if tshark is still alive.
                thread::sleep(Duration::from_millis(10));
                if let Ok(Some(_)) = tshark_process.try_wait() {
                    // TShark died
                    break;
                }
            }
            Err(_) => {
                // Parsing error (truncated packet at end of file), ignore and wait
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    let _ = tshark_process.kill();
    // Cleanup takes a moment to release file lock
    thread::sleep(Duration::from_millis(500));
    cleanup_file(&capture_file);
    eprintln!("[*] Finished. Scanned {} packets.", packet_count);
}

fn save_to_file(path: &str, id: u64, content: &str) {
    use std::fs::OpenOptions;
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "Match packet #{}\n{}\n", id, content);
    }
}

fn generate_temp_file_path() -> PathBuf {
    use rand::Rng;
    let id: u32 = rand::thread_rng().gen();
    let mut temp_dir = std::env::temp_dir();
    temp_dir.push(format!("vgksys_{}.pcapng", id));
    temp_dir
}

fn cleanup_file(path: &PathBuf) {
    if path.exists() {
        let _ = fs::remove_file(path);
    }
}