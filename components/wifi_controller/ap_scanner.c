#include "ap_scanner.h"

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"

static const char* TAG = "wifi_controller/ap_scanner";
static wifictl_ap_records_t ap_records;

void wifictl_scan_nearby_aps(){
    ESP_LOGD(TAG, "Scanning nearby APs...");

    ap_records.count = CONFIG_SCAN_MAX_AP;

    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE
    };
    
    ESP_ERROR_CHECK(esp_wifi_scan_start(&scan_config, true));
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&ap_records.count, ap_records.records));
    ESP_LOGI(TAG, "Found %u APs.", ap_records.count);
    ESP_LOGD(TAG, "Scan done.");
}

void wifictl_store_scan_results(const wifi_ap_record_t *list, uint16_t count)
{
    if (count > CONFIG_SCAN_MAX_AP) count = CONFIG_SCAN_MAX_AP;
    ap_records.count = count;
    for (uint16_t i = 0; i < count; ++i) {
        ap_records.records[i] = list[i]; // struct copy
        
    //     // Print SSID and BSSID (MAC address)
    //     ESP_LOGI(TAG, "[%2d] SSID: %s | BSSID: %02X:%02X:%02X:%02X:%02X:%02X | RSSI: %d",
    //              i + 1,
    //              (char *)list[i].ssid,
    //              list[i].bssid[0],
    //              list[i].bssid[1],
    //              list[i].bssid[2],
    //              list[i].bssid[3],
    //              list[i].bssid[4],
    //              list[i].bssid[5],
    //              list[i].rssi);
    
    }
}

const wifictl_ap_records_t *wifictl_get_ap_records() {
    return &ap_records;
}


const wifi_ap_record_t *wifictl_find_ap_by_bssid(const uint8_t bssid[6]) {
    for (unsigned i = 0; i < ap_records.count; ++i) {
        if (memcmp(ap_records.records[i].bssid, bssid, 6) == 0) return &ap_records.records[i];
    }
    return NULL;
}