#include "wifi_controller.h"

#include <stdio.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "wsl_bypasser.h"
#include "freertos/semphr.h"

#define MAX_TRACKED_APS 6
#define MAX_CLIENTS_PER_AP 32


typedef struct {
    uint8_t ap_bssid[6];
    uint8_t clients[MAX_CLIENTS_PER_AP][6];
    int client_count;
} tracked_ap_clients_t;

static tracked_ap_clients_t tracked_aps[MAX_TRACKED_APS];
static uint8_t current_target_bssid[6] = {0};
static bool target_set = false;
static SemaphoreHandle_t clients_lock = NULL;
static uint8_t whitelisted_macs[8][6];
static int whitelist_count = 0;

static const char* TAG = "wifi_controller";
static bool wifi_init = false;
static uint8_t original_mac_ap[6];

static void wifi_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data){
    // Empty for now
}

static void wifi_init_apsta(){
    if (wifi_init) {
        ESP_LOGW(TAG, "Wi-Fi already initialized, skipping...");
        return;
    }

    ESP_LOGI(TAG, "Initializing Wi-Fi in APSTA mode...");

    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");

    if (sta_netif == NULL || ap_netif == NULL) {
        ESP_ERROR_CHECK(esp_netif_init());
        
        if (ap_netif == NULL) {
            ap_netif = esp_netif_create_default_wifi_ap();
        }
        if (sta_netif == NULL) {
            esp_netif_create_default_wifi_sta();
        }
    }

    wifi_mode_t current_mode;
    if (esp_wifi_get_mode(&current_mode) == ESP_OK) {
        // WiFi already initialized
        ESP_LOGI(TAG, "WiFi already initialized in mode %d", current_mode);
        wifi_init = true;
        
        if (original_mac_ap[0] == 0 && original_mac_ap[1] == 0) {
            ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, original_mac_ap));
        }
        return;
    }
    wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_init_config));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));

    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, original_mac_ap));

    ESP_ERROR_CHECK(esp_wifi_start());
    wifi_init = true;
    ESP_LOGI(TAG, "Wi-Fi initialization complete");
}

void wifictl_ap_start(wifi_config_t *wifi_config) {
    ESP_LOGD(TAG, "Starting AP...");
    
    if(!wifi_init){
        wifi_init_apsta();
    }

    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, wifi_config));
    ESP_LOGI(TAG, "AP started with SSID=%s", wifi_config->ap.ssid);
}

void wifictl_ap_stop(){
    ESP_LOGD(TAG, "Stopping AP...");
    wifi_config_t wifi_config = {
        .ap = {
            .max_connection = 0
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_config));
    ESP_LOGD(TAG, "AP stopped");
}

void wifictl_mgmt_ap_start(){
    wifi_config_t mgmt_wifi_config = {
        .ap = {
            .ssid = CONFIG_MGMT_AP_SSID,
            .ssid_len = strlen(CONFIG_MGMT_AP_SSID),
            .password = CONFIG_MGMT_AP_PASSWORD,
            .max_connection = CONFIG_MGMT_AP_MAX_CONNECTIONS,
            .authmode = WIFI_AUTH_WPA2_PSK
        },
    };
    wifictl_ap_start(&mgmt_wifi_config);
}

void wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap_record, const char password[]){
    ESP_LOGD(TAG, "Connecting STA to AP...");
    if(!wifi_init){
        wifi_init_apsta();
    }

    wifi_config_t sta_wifi_config = {
        .sta = {
            .channel = ap_record->primary,
            .scan_method = WIFI_FAST_SCAN,
            .pmf_cfg.capable = false,
            .pmf_cfg.required = false
        },
    };
    mempcpy(sta_wifi_config.sta.ssid, ap_record->ssid, 32);

    if(password != NULL){
        if(strlen(password) >= 64) {
            ESP_LOGE(TAG, "Password is too long. Max supported length is 64");
            return;
        }
        memcpy(sta_wifi_config.sta.password, password, strlen(password) + 1);
    }

    ESP_LOGD(TAG, ".ssid=%s", sta_wifi_config.sta.ssid);

    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &sta_wifi_config));
    ESP_ERROR_CHECK(esp_wifi_connect());
}

void wifictl_sta_disconnect(){
    ESP_ERROR_CHECK(esp_wifi_disconnect());
}

void wifictl_set_ap_mac(const uint8_t *mac_ap){
    ESP_LOGD(TAG, "Changing AP MAC address...");
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, mac_ap));
}

void wifictl_get_ap_mac(uint8_t *mac_ap){
    esp_wifi_get_mac(WIFI_IF_AP, mac_ap);
}

void wifictl_restore_ap_mac(){
    ESP_LOGD(TAG, "Restoring original AP MAC address...");
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, original_mac_ap));
}

void wifictl_get_sta_mac(uint8_t *mac_sta){
    esp_wifi_get_mac(WIFI_IF_STA, mac_sta);
}

void wifictl_mark_initialized(void){
    ESP_LOGI(TAG, "Marking WiFi as already initialized by external code");
    wifi_init = true;
    esp_wifi_get_mac(WIFI_IF_AP, original_mac_ap);
}

void wifictl_set_channel(uint8_t channel){
    if((channel == 0) || (channel >  13)){
        ESP_LOGE(TAG,"Channel out of range. Expected value from <1,13> but got %u", channel);
        return;
    }
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

static void ensure_clients_lock() {
    if (clients_lock == NULL) {
        clients_lock = xSemaphoreCreateMutex();
    }
}


bool wifictl_is_target_set(void) {
    ensure_clients_lock();
    bool set;
    if (xSemaphoreTake(clients_lock, portMAX_DELAY) == pdTRUE) {
        set = target_set;
        xSemaphoreGive(clients_lock);
    } else {
        set = false;
    }
    return set;
}

void wifictl_get_target_bssid(uint8_t *out_bssid) {
    if (out_bssid == NULL) return;
    ensure_clients_lock();
    if (xSemaphoreTake(clients_lock, portMAX_DELAY) == pdTRUE) {
        memcpy(out_bssid, current_target_bssid, 6);
        xSemaphoreGive(clients_lock);
    } else {
        memset(out_bssid, 0, 6);
    }
}

void wifictl_stop_sniffer_and_clear_target(void) {
    ESP_LOGI(TAG, "Stopping sniffer and clearing tracked clients/target");
    // stop promiscuous mode
    esp_wifi_set_promiscuous(false);

    // clear tracked clients for current target
    ensure_clients_lock();
    if (xSemaphoreTake(clients_lock, portMAX_DELAY) == pdTRUE) {
        // clear tracked entry that matches current_target_bssid
        for (int i = 0; i < MAX_TRACKED_APS; i++) {
            if (memcmp(tracked_aps[i].ap_bssid, current_target_bssid, 6) == 0) {
                memset(&tracked_aps[i], 0, sizeof(tracked_ap_clients_t));
                break;
            }
        }
        // clear the current target and mark unset
        memset(current_target_bssid, 0, sizeof(current_target_bssid));
        target_set = false;
        xSemaphoreGive(clients_lock);
    }
}


void wifictl_set_target_bssid(const uint8_t *bssid) {
    ensure_clients_lock();
    xSemaphoreTake(clients_lock, portMAX_DELAY);
    memcpy(current_target_bssid, bssid, 6);
    target_set = true;
    // ensure tracker entry exists for this bssid
    for (int i=0;i<MAX_TRACKED_APS;i++){
        if (memcmp(tracked_aps[i].ap_bssid, bssid, 6) == 0) {
            // already present
            xSemaphoreGive(clients_lock);
            return;
        }
    }
    // find empty slot
    for (int i=0;i<MAX_TRACKED_APS;i++){
        bool empty = true;
        for (int j=0;j<6;j++) if (tracked_aps[i].ap_bssid[j] != 0) { empty = false; break; }
        if (empty) {
            memcpy(tracked_aps[i].ap_bssid, bssid, 6);
            tracked_aps[i].client_count = 0;
            break;
        }
    }
    xSemaphoreGive(clients_lock);
}

void wifictl_clear_target_bssid(void) {
    ensure_clients_lock();
    xSemaphoreTake(clients_lock, portMAX_DELAY);
    memset(current_target_bssid, 0, sizeof(current_target_bssid));
    target_set = false;
    xSemaphoreGive(clients_lock);
}

void wifictl_clear_tracked_clients_for_bssid(const uint8_t *bssid) {
    ensure_clients_lock();
    xSemaphoreTake(clients_lock, portMAX_DELAY);
    for (int i=0;i<MAX_TRACKED_APS;i++){
        if (memcmp(tracked_aps[i].ap_bssid, bssid, 6)==0) {
            memset(&tracked_aps[i], 0, sizeof(tracked_ap_clients_t));
            break;
        }
    }
    xSemaphoreGive(clients_lock);
}

void wifictl_clear_all_tracked_clients(void) {
    ensure_clients_lock();
    xSemaphoreTake(clients_lock, portMAX_DELAY);
    memset(tracked_aps, 0, sizeof(tracked_aps));
    xSemaphoreGive(clients_lock);
}

static bool is_whitelisted(const uint8_t *mac) {
    for (int i=0;i<whitelist_count;i++){
        if (memcmp(whitelisted_macs[i], mac, 6)==0) return true;
    }
    return false;
}

void wifictl_whitelist_mac(const uint8_t *mac) {
    ensure_clients_lock();
    xSemaphoreTake(clients_lock, portMAX_DELAY);
    if (whitelist_count < (int)(sizeof(whitelisted_macs)/6)) {
        memcpy(whitelisted_macs[whitelist_count++], mac, 6);
    }
    xSemaphoreGive(clients_lock);
}

void wifictl_remove_whitelist_mac(const uint8_t *mac) {
    ensure_clients_lock();
    xSemaphoreTake(clients_lock, portMAX_DELAY);
    for (int i = 0; i < whitelist_count; ++i) {
        if (memcmp(whitelisted_macs[i], mac, 6) == 0) {
            // move last into this slot (or zero out)
            if (i != whitelist_count - 1) {
                memcpy(whitelisted_macs[i], whitelisted_macs[whitelist_count - 1], 6);
            }
            memset(whitelisted_macs[whitelist_count - 1], 0, 6);
            --whitelist_count;
            ESP_LOGI(TAG, "Removed MAC from whitelist %02X:%02X:%02X:%02X:%02X:%02X",
                     mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
            break;
        }
    }
    xSemaphoreGive(clients_lock);
}

void wifictl_track_client(const uint8_t *ap_bssid, const uint8_t *sta_mac) {
    if (is_whitelisted(sta_mac)) return;
    ensure_clients_lock();
    xSemaphoreTake(clients_lock, portMAX_DELAY);
    // find ap entry
    int slot = -1;
    for (int i=0;i<MAX_TRACKED_APS;i++){
        if (memcmp(tracked_aps[i].ap_bssid, ap_bssid, 6)==0) { slot = i; break; }
    }
    if (slot == -1) {
        // try to create slot
        for (int i=0;i<MAX_TRACKED_APS;i++){
            bool empty = true;
            for (int j=0;j<6;j++) if (tracked_aps[i].ap_bssid[j] != 0) { empty = false; break; }
            if (empty) {
                slot = i;
                memcpy(tracked_aps[i].ap_bssid, ap_bssid, 6);
                tracked_aps[i].client_count = 0;
                break;
            }
        }
    }
    if (slot == -1) {
        // no space
        xSemaphoreGive(clients_lock);
        return;
    }
    // check duplicate
    for (int c=0;c<tracked_aps[slot].client_count;c++){
        if (memcmp(tracked_aps[slot].clients[c], sta_mac, 6)==0) {
            xSemaphoreGive(clients_lock);
            return;
        }
    }
    if (tracked_aps[slot].client_count < MAX_CLIENTS_PER_AP) {
        memcpy(tracked_aps[slot].clients[tracked_aps[slot].client_count++], sta_mac, 6);
        ESP_LOGI("wifictl", "Tracked client %02X:%02X:%02X:%02X:%02X:%02X for BSSID %02X:%02X:%02X:%02X:%02X:%02X",
                 sta_mac[0],sta_mac[1],sta_mac[2],sta_mac[3],sta_mac[4],sta_mac[5],
                 ap_bssid[0],ap_bssid[1],ap_bssid[2],ap_bssid[3],ap_bssid[4],ap_bssid[5]);
    }
    xSemaphoreGive(clients_lock);
}

void wifictl_untrack_client(const uint8_t *mac) {
    ensure_clients_lock();
    xSemaphoreTake(clients_lock, portMAX_DELAY);

    for (int i = 0; i < sizeof(tracked_aps) / sizeof(tracked_aps[0]); ++i) {
        for (int j = 0; j < tracked_aps[i].client_count; ++j) {
            if (memcmp(tracked_aps[i].clients[j], mac, 6) == 0) {
                // remove client from list
                if (j != tracked_aps[i].client_count - 1) {
                    memcpy(tracked_aps[i].clients[j], tracked_aps[i].clients[tracked_aps[i].client_count - 1], 6);
                }
                tracked_aps[i].client_count--;
                ESP_LOGI(TAG, "Untracked client " MACSTR, MAC2STR(mac));
                break;
            }
        }
    }

    xSemaphoreGive(clients_lock);
}

/**
 * Deauth all tracked clients for given AP bssid.
 */
void wifictl_deauth_tracked_clients(const uint8_t *ap_bssid) {
    ensure_clients_lock();
    xSemaphoreTake(clients_lock, portMAX_DELAY);
    for (int i=0;i<MAX_TRACKED_APS;i++){
        if (memcmp(tracked_aps[i].ap_bssid, ap_bssid, 6)==0) {
            for (int c=0;c<tracked_aps[i].client_count;c++){
                // Skip any whitelisted clients (e.g., stations connected to our rogue AP)
                if (!is_whitelisted(tracked_aps[i].clients[c])) {
                    wsl_bypasser_send_deauth_to_sta(ap_bssid, tracked_aps[i].clients[c]);
                }
            }
            break;
        }
    }
    xSemaphoreGive(clients_lock);
}