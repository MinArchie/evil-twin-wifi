
#pragma once

#include <stdint.h>
#include <stdbool.h>

extern const char* RISK_CLASSES[3];

struct ScannedNetwork {
  char ssid[33];
  char bssid_str[18];
  int32_t rssi;
  int32_t channel;
  bool hidden;
  uint8_t authmode;
  char authString[32];
};

struct HotspotConfig {
  char ssid[33];
  char bssid_str[18];
  int32_t rssi;
  int32_t channel;
  bool hidden;
  uint8_t authmode;
  char authString[32];
  char password[64];
};

extern struct HotspotConfig g_hotspotConfig;