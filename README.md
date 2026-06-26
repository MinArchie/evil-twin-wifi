# Evil Twin WiFi — ESP32

An ESP-IDF project that turns an ESP32 into a WiFi security assessment tool. It scans nearby networks, classifies them using an on-device TensorFlow Lite model, clones a target AP, launches a deauthentication attack, and serves a captive portal to capture credentials.

Built for educational/research use.

> **Companion board:** [uart-slave](https://github.com/MinArchie/uart-slave) — receives BSSID commands over UART and fires raw 802.11 deauthentication frames independently.


---

## Hardware

- ESP32 (target: `esp32`)
- A secondary ESP32 acting as a UART slave for sending deauth frames
  - UART1: TX = GPIO17, RX = GPIO16, 115200 baud

---

## Features

- **Network Scanner** — active WiFi scan with per-network risk classification (Good / Medium / Risky) using a TFLite Micro model trained on RSSI, auth mode, and hidden SSID
- **Evil Twin AP** — clones a target network (SSID, channel, auth mode) with optional MAC spoofing and UTF-8 SSID obfuscation
- **Deauth Attack** — periodically sends the target BSSID over UART to a slave ESP32 which transmits deauth frames
- **Captive Portal** — intercepts all DNS queries (port 53 → 192.168.4.1) and redirects clients to a login page; credentials are logged via UART
- **Web Interface** — served at `http://192.168.4.1`, handles scan, clone, hotspot config, and attack control

---

## How It Works

```
Boot
 └─ Load TFLite model
 └─ Init UART master (slave handles deauth transmission)
 └─ Start WiFi: AP + STA simultaneously
 └─ Start DNS server (all queries → 192.168.4.1)
 └─ Start HTTP server on port 80

User connects to ESP32_Control_AP
 └─ Captive portal redirects to web UI
 └─ Scan → networks listed with risk level
 └─ Select target → clone AP with same SSID/channel/auth
 └─ Deauth attack starts (UART → slave every 1s)
 └─ Victims connect to rogue AP → captive portal → credentials captured
```

---

## Default Config

| Setting | Value |
|---|---|
| Control AP SSID | `ESP32_Control_AP` |
| Control AP Password | `12345678` |
| Control AP Channel | 6 |
| AP IP | `192.168.4.1` |
| UART Baud | 115200 |

---

## Project Structure

```
main/
  main.c            — entry point, WiFi + server init
  wifi_handler.c    — rogue AP creation, deauth logic, event handling
  web_server.c      — HTTP endpoints and HTML UI
  uart_deauth.c     — UART master protocol (sends BSSID to slave)
  dns_server.c      — DNS server for captive portal redirection
  tflite_handler.cpp — TFLite Micro inference (network risk classification)
  project_types.h   — shared structs (ScannedNetwork, HotspotConfig)

components/
  wifi_controller/  — AP scanner, packet sniffer, WiFi control primitives
```

---

## Build & Flash

Requires [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/) v5.x.

```bash
idf.py set-target esp32
idf.py build
idf.py -p PORT flash monitor
```

---

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Do not use it against networks you do not own or have explicit permission to test.
