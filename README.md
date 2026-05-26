
# Evil Twin Wi-Fi — ESP32 Master Controller

One half of a two-board 802.11 security research platform. This board runs an on-device neural network to classify nearby Wi-Fi networks, hosts a rogue access point (evil twin), and commands a dedicated deauth board over UART.

Built with **C/C++**, **ESP-IDF**, and **TensorFlow Lite Micro**.

> **Companion board:** [uart-slave](https://github.com/MinArchie/uart-slave) — receives BSSID commands over UART and fires raw 802.11 deauthentication frames independently.

---

## What this board does

- **Scans & classifies nearby networks** — a TFLite Micro neural network running on-chip rates each AP as *Good*, *Medium*, or *Risky* using signal strength, auth mode, and SSID visibility
- **Evil twin AP** — clones a target network's SSID, BSSID, channel, and auth configuration
- **UART deauth trigger** — on user action, serializes the target BSSID into a framed UART message and dispatches it to the slave board
- **AP+STA dual mode** — simultaneously connects to an upstream network and runs its own AP so the dashboard stays reachable
- **Browser dashboard** — on-device HTTP server serves a live scan table with per-network risk badges and one-click clone/deauth actions


---

## Architecture

```
main/
  main.c              — boot: init TFLite → init Wi-Fi → start HTTP server
  tflite_handler.cpp  — TFLite Micro inference (auth, RSSI, hidden → Good/Medium/Risky)
  wifi_handler.c      — AP+STA init, rogue AP setup, deauth timer, event routing
  web_server.c        — HTTP routes: /, /scan, /hotspot, /clone, /deauth
components/
  wifi_controller/    — AP scanner, packet sniffer, MAC spoofing
  wsl_bypasser/       — raw 802.11 frame injection (bypasses ESP-IDF WSL check)
```

## Stack

| Layer | Technology |
|---|---|
| Hardware | ESP32 |
| RTOS / SDK | FreeRTOS · ESP-IDF |
| ML runtime | TensorFlow Lite Micro |
| Networking | ESP-IDF `esp_wifi` · `esp_http_server` |
| Language | C / C++ |

## Build & Flash

Requires [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/) v5.x.

```bash
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

Once running, connect to the ESP32's AP and navigate to its IP in a browser.

---

## Why two boards

An ESP32 radio can't simultaneously run a stable access point and inject raw management frames on a target channel. Board 1 handles scanning, the evil twin AP, and the control interface. Board 2 handles continuous deauth injection — triggered by UART from this board — without disrupting AP operation.
---

> **For authorized security research and educational use only.**
