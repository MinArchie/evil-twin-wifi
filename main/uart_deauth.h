// #ifndef DEAUTH_H
// #define DEAUTH_H

// #include <stdint.h>
// #include <stddef.h>
// #include "esp_wifi_types.h"

// /* Public API for the master-side UART/timer broadcast */

// /* Initialize UART on master (call once during startup) */
// void uart_init_master(void);

// /* Start periodic broadcast: send BSSID periodically (period_sec seconds) */
// void attack_method_broadcast(const wifi_ap_record_t *ap_record, unsigned period_sec);

// /* Stop the periodic broadcast and free resources */
// void attack_method_broadcast_stop(void);

// #endif // DEAUTH_H



#ifndef DEAUTH_H
#define DEAUTH_H

#include <stdint.h>
#include <stddef.h>
#include "esp_wifi_types.h"

/* Public API for the master-side UART/timer broadcast */

/* Initialize UART on master (call once during startup) */
void uart_init_master(void);

/* Start periodic broadcast: send BSSID periodically (period_sec seconds) */
void attack_method_broadcast(const wifi_ap_record_t *ap_record, unsigned period_sec);

/* Stop the periodic broadcast and free resources */
void attack_method_broadcast_stop(void);

#endif // DEAUTH_H
