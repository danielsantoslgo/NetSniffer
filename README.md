# 📡 NetSniffer — Real-Time Network Packet Analyzer in Go

`NetSniffer` is a powerful real-time packet analyzer written in Go. It captures and logs packets from a selected network interface, prints simplified JSON summaries, and saves full packet data into a `.pcap` file for later analysis using tools like Wireshark or tcpdump.

---

## 🚀 Features

* 🔍 Lists all available network interfaces.
* ⚖️ Applies customizable BPF filters (default: `tcp`).
* 📉 Displays real-time packet summaries in structured JSON format:

  * Timestamp
  * Source IP
  * Destination IP
  * Protocol
  * Packet length
* 📃 Stores raw packets in `capture.pcap` for offline inspection.
* ⏹ Handles `Ctrl+C` to exit cleanly and finalize output.

---

## ⚙️ Requirements

* **Go 1.18+**
* **libpcap** installed on your system (usually preinstalled on Linux/macOS)

Install Go dependency:

```bash
go get github.com/google/gopacket
```

---

## 🦖 How to Run

```bash
go run NetSniffer.go
```

### ✅ Steps

1. Select the interface number you want to sniff.
2. Watch real-time JSON output for each packet.
3. Inspect `capture.pcap` later in any network analyzer.

---

## 📅 Example Output

```json
{
  "timestamp": "2025-05-07T18:21:33Z",
  "src_ip": "192.168.1.10",
  "dst_ip": "93.184.216.34",
  "protocol": "TCP",
  "length": 74
}
```

---

## 🔧 Customize Filter

To modify the BPF filter, change the following line in `main.go`:

```go
filter := "tcp" // Can be "udp", "port 443", "ip host 192.168.1.1", etc.
```

---

## 📂 PCAP Output

Captured data is saved to `capture.pcap`. You can analyze it later with:

```bash
wireshark capture.pcap
# or
tcpdump -r capture.pcap
```

---

## ⚠️ Legal Disclaimer

This tool is intended for educational and authorized testing purposes only. Unauthorized packet sniffing may violate local laws and regulations. Use responsibly and only on networks you are permitted to monitor.

---

Happy sniffing — responsibly! 🤌🚀
