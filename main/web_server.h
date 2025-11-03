// main/web_server.h
#pragma once

#include "esp_http_server.h"
#include "esp_event.h"
#include <stdint.h>

ESP_EVENT_DECLARE_BASE(WEB_EVENTS);
enum {
    WEB_EVENT_DEAUTH_REQUEST,
    WEB_EVENT_ATTACK_RESET,
};

typedef struct {
    uint8_t bssid[6];   // target AP MAC (6 bytes)
    uint8_t type;       // attack type
    uint8_t method;     // attack method
    uint8_t timeout;    // timeout seconds
} attack_request_t;


httpd_handle_t start_webserver(void);

void stop_webserver(httpd_handle_t server);
void wifictl_set_target_bssid(const uint8_t *bssid);
void wifictl_clear_target_bssid(void);
void wifictl_track_client(const uint8_t *ap_bssid, const uint8_t *sta_mac);
void wifictl_deauth_tracked_clients(const uint8_t *ap_bssid);
void wifictl_clear_tracked_clients_for_bssid(const uint8_t *bssid);
void wifictl_clear_all_tracked_clients(void);
void wifictl_whitelist_mac(const uint8_t *mac);