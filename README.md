# Evil Twin Wi-Fi — ESP32 Security Research Tool

A bare-metal embedded security tool that runs an on-device neural network to classify Wi-Fi network risk, then enables targeted wifi deauthentication and cloning attacks — all controlled from a browser-based dashboard served directly by the ESP32.

Built with **C/C++**, **ESP-IDF**, and **TensorFlow Lite Micro**.

---

## What it does

- **Scans & classifies nearby networks** using a TFLite Micro neural network running on-chip, rating each access point as *Good*, *Medium*, or *Risky* based on signal strength, auth mode, and SSID visibility
- **Evil twin AP** — clones a target network's SSID, BSSID, channel, and auth mode to stand up a rogue access point
- **Deauthentication attacks** — injects raw IEEE 802.11 deauth frames via a WSL security layer bypass, periodically broadcasting to disconnect clients from a target AP
- **AP+STA dual mode** — simultaneously connects to an upstream network and runs its own access point, so the control dashboard is reachable over Wi-Fi without additional hardware
- **Browser dashboard** — on-device HTTP server (ESP-IDF `httpd`) serves a live scan table with per-network risk badges and one-click clone/deauth actions

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

> **For authorized security research and educational use only.**
