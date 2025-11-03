// main/web_server.h
#pragma once

#include "esp_http_server.h"
#include "esp_event.h"

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