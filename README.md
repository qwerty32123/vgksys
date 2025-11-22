Here is a complete and professional `README.md` for your tool. It explains how to build it, how to find your network interface, and how to use the "Tunnel" feature to pipe data to other programs.

---

# VGKSYS - Live Packet Signature Filter

**VGKSYS** is a high-performance Rust CLI tool that acts as a live filter for network traffic. It wraps **Wireshark (TShark)** to capture packets in real-time, parses them, and scans for specific byte signatures (currently hardcoded as `S\sa\sn\sg\so\so\sn`).

## 🚀 Prerequisites

1.  **Rust (Cargo):** [Install here](https://rustup.rs/) if you haven't already.
2.  **Wireshark (TShark):**
    *   **Windows:** Download the [Wireshark Installer](https://www.wireshark.org/download.html).
        *   ⚠️ **Important:** During install, check **"Add Wireshark to the system PATH"**.
    *   **Linux:** `sudo apt install tshark`

## 🛠️ Building

Clone the project and build the release binary for maximum speed:

```bash
cargo build --release
```
The executable will be located at: `target/release/vgksys.exe` (Windows) or `target/release/vgksys` (Linux).

---

## 📖 Usage Guide

### 1. Find your Network Interface
Before running the tool, you need to know which Network Card identifier (index) to listen on.

Run this command in your terminal:
```bash
tshark -D
```

**Example Output:**
```text
1. \Device\NPF_{...} (Wi-Fi)
2. \Device\NPF_{...} (Ethernet)
3. \Device\NPF_Loopback (Adapter for loopback traffic capture)
```
*If you are using Wi-Fi, your interface ID is likely **1**. If using Ethernet, it might be **2**.*

### 2. Basic Scan
Run the tool as **Administrator** (Windows) or **Root** (Linux) to capture packets.

**Windows (PowerShell/CMD):**
```powershell
# Listen on Interface 1
./target/release/vgksys.exe -i 1
```

**Linux:**
```bash
# Listen on eth0
sudo ./target/release/vgksys -i eth0
```

### 3. Save Matches to File
You can simultaneously print to the screen and append matches to a log file:

```bash
vgksys.exe -i 1 --output found_signatures.txt
```

---

## 🚇 Using the "Tunnel" (Piping)

Because `vgksys` outputs matches directly to **Standard Output (STDOUT)**, you can pipe the output into other tools for further processing, alerting, or live monitoring.

### Example A: Live Grep (Filter within the match)
If you only want to see lines containing specific protocol info (e.g., "TCP") inside the matched packets:

**Windows:**
```powershell
vgksys.exe -i 1 | findstr "TCP"
```

**Linux:**
```bash
sudo ./vgksys -i eth0 | grep "TCP"
```

### Example B: Live File Streaming
If you want to view the output on screen *and* save a raw copy of the output to a file using shell redirection:

**Linux/Mac (tee):**
```bash
sudo ./vgksys -i eth0 | tee raw_log.log
```

**Windows (Powershell):**
```powershell
./vgksys.exe -i 1 | Tee-Object -FilePath "raw_log.log"
```

---

## ❓ Troubleshooting

### "TShark: program not found"
1.  Ensure Wireshark is installed.
2.  Run `tshark -v` in a new terminal. If it fails, add `C:\Program Files\Wireshark` to your **System PATH** environment variables.

### "No packets found" / "Capture session could not be initiated"
1.  **Run as Administrator.** Network capture requires elevated privileges.
2.  Double-check your interface ID using `tshark -D`.

### "The system cannot find the file specified"
The tool uses a temporary file buffer. If your antivirus blocks the creation of temporary `.pcap` files, this error happens.
*   **Fix:** Add an exclusion for the folder `%TEMP%` or run the tool with Antivirus disabled temporarily to test.