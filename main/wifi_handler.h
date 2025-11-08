// main/wifi_handler.h
#pragma once

#include <stdint.h>
#include <esp_wifi_types.h>
#include "wifi_controller.h"

typedef enum {
    READY,      ///< no attack is in progress and results from previous attack run are available.
    RUNNING,    ///< attack is in progress, attack_status_t.content may not be consistent.
    FINISHED,   ///< last attack finsihed and results are available.
    TIMEOUT     ///< last attack timed out. This option will be moved as sub category of FINISHED state.
} attack_state_t;

typedef struct {
    uint8_t type;
    uint8_t method;
    uint8_t timeout;
    const wifi_ap_record_t *ap_record;
    char password[64];
    bool hidden;
} attack_config_t;

typedef enum {
    ATTACK_TYPE_PASSIVE,
    ATTACK_TYPE_HANDSHAKE,
    ATTACK_TYPE_PMKID,
    ATTACK_TYPE_DOS
} attack_type_t;

typedef struct {
    uint8_t state;  ///< attack_state_t
    uint8_t type;   ///< attack_type_t
    uint16_t content_size;
    char *content;
} attack_status_t;

/**
 * @brief Initializes the Wi-Fi in AP+STA mode.
 * This registers event handlers and sets up the network interfaces.
 */
void wifi_init_ap_sta(void);

/**
 * @brief Starts the SoftAP based on the g_hotspotConfig global variable.
 */
void start_hotspot(void);

/**
 * @brief Gets the C-string name for a Wi-Fi authentication mode.
 * Replaces getAuthModeName().
 */
const char* get_auth_mode_name(uint8_t authmode);


typedef enum{
    ATTACK_DOS_METHOD_ROGUE_AP,
    ATTACK_DOS_METHOD_BROADCAST,
    ATTACK_DOS_METHOD_COMBINE_ALL
} attack_dos_methods_t;

void attack_method_rogueap(const attack_config_t  *attack_config, int mode);
void attack_dos_start(attack_config_t *attack_config);
void attack_dos_stop();

/**
 * @brief Sends a raw 802.11 deauthentication frame.
 * This is a direct copy of your sendDeauthFrame() function.
 */
void send_deauth_frame(const uint8_t* bssid, const uint8_t* sta);