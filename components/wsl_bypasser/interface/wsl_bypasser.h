
#ifndef WSL_BYPASSER_H
#define WSL_BYPASSER_H

#include "esp_wifi_types.h"
#include <stdint.h>

void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size);

void wsl_bypasser_send_deauth_frame(const wifi_ap_record_t *ap_record);

void wsl_bypasser_send_deauth_to_sta(const uint8_t *ap_bssid, const uint8_t *sta);

#endif