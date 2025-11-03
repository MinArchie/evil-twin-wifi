#include "sniffer.h"

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "wifi_controller.h"
#include <string.h>

extern void wifictl_track_client(const uint8_t *ap_bssid, const uint8_t *sta_mac);
extern void wifictl_deauth_tracked_clients(const uint8_t *ap_bssid);

// static void copy_mac(uint8_t *dst, const uint8_t *src) { memcpy(dst, src, 6); }

static const char *TAG = "sniffer"; 

ESP_EVENT_DEFINE_BASE(SNIFFER_EVENTS);


static void frame_handler(void *buf, wifi_promiscuous_pkt_type_t type) {
    ESP_LOGV(TAG, "Captured frame %d.", (int) type);

    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) buf;
    const uint8_t *payload = frame->payload;
    // sanity: ensure size at least 24 (802.11 header)
    if (frame->rx_ctrl.sig_len < 24) {
        // still post event, but skip tracking
    } else {
        // addresses in 802.11 header: offsets depend on frame control but common layout:
        const uint8_t *addr1 = payload + 4;
        const uint8_t *addr2 = payload + 10;
        const uint8_t *addr3 = payload + 16;

        // If there is a current target bssid, try to associate client and notify tracker
        // We'll call wifictl_track_client when either addr1/addr2/addr3 matches target
        extern uint8_t current_target_bssid[6];
        extern bool target_set;
        if (wifictl_is_target_set()) {
        uint8_t target_bssid[6];
        wifictl_get_target_bssid(target_bssid);
        if (memcmp(addr1, target_bssid, 6) == 0) {
            wifictl_track_client(target_bssid, (uint8_t *)addr2);
        } else if (memcmp(addr2, target_bssid, 6) == 0) {
            wifictl_track_client(target_bssid, (uint8_t *)addr1);
        } else if (memcmp(addr3, target_bssid, 6) == 0) {
            wifictl_track_client(target_bssid, (uint8_t *)addr2);
        }
    }
    }

    int32_t event_id;
    switch (type) {
        case WIFI_PKT_DATA:
            event_id = SNIFFER_EVENT_CAPTURED_DATA;
            break;
        case WIFI_PKT_MGMT:
            event_id = SNIFFER_EVENT_CAPTURED_MGMT;
            break;
        case WIFI_PKT_CTRL:
            event_id = SNIFFER_EVENT_CAPTURED_CTRL;
            break;
        default:
            return;
    }

    ESP_ERROR_CHECK(esp_event_post(SNIFFER_EVENTS, event_id, frame, frame->rx_ctrl.sig_len + sizeof(wifi_promiscuous_pkt_t), portMAX_DELAY));
}

void wifictl_sniffer_filter_frame_types(bool data, bool mgmt, bool ctrl) {
    wifi_promiscuous_filter_t filter = { .filter_mask = 0 };
    if(data) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
    }
    else if(mgmt) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_MGMT;
    }
    else if(ctrl) {
        filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;
    }
    esp_wifi_set_promiscuous_filter(&filter);
}

void wifictl_sniffer_start(uint8_t channel) {
    ESP_LOGI(TAG, "Starting promiscuous mode...");
    // Do not deauth our SoftAP clients here; we only want to target
    // clients associated with the selected external BSSID via crafted frames.
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&frame_handler);
}

void wifictl_sniffer_stop() {
    ESP_LOGI(TAG, "Stopping promiscuous mode...");
    esp_wifi_set_promiscuous(false);
}