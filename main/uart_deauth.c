
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
#include "driver/gpio.h"

#include "driver/uart.h"
#include <stdlib.h>

static QueueHandle_t uart_tx_queue;

#define MASTER_UART_TX_GPIO GPIO_NUM_17
#define MASTER_UART_RX_GPIO GPIO_NUM_16

static const char *TAG = "MASTER";
#define UART_PORT UART_NUM_1
#define UART_BAUD 115200
static esp_timer_handle_t deauth_timer_handle;
static uint8_t *g_bssid_heap = NULL;

#define MAGIC 0x7E
#define MSG_BSSID 0x01

static uint8_t xor8(const uint8_t *d, size_t n) {
    uint8_t x = 0; for (size_t i = 0; i < n; ++i) x ^= d[i]; return x;
}
static void uart_tx_task(void *arg)
{
    uint8_t bssid[6];
    while (1) {
        if (xQueueReceive(uart_tx_queue, &bssid, portMAX_DELAY)) {
            uint8_t frame[1 + 1 + 6 + 1];
            size_t p = 0;
            frame[p++] = MAGIC;
            frame[p++] = MSG_BSSID;
            memcpy(&frame[p], bssid, 6); p += 6;
            frame[p++] = xor8(&frame[1], 1 + 6);

            ESP_LOGI("Writing bytes to UART", "Sending deauth frame for BSSID %02X:%02X:%02X:%02X:%02X:%02X",
                     bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
            uart_write_bytes(UART_PORT, (const char *)frame, p);
            ESP_LOGD(TAG, "TX task sent frame for %02X:%02X:%02X:%02X:%02X:%02X",
                     bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
        }
    }
}


void uart_init_master(void)
{
    uart_config_t cfg = {
        .baud_rate = UART_BAUD,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };
    ESP_ERROR_CHECK(uart_param_config(UART_PORT, &cfg));

    // map to actual pins
    ESP_ERROR_CHECK(uart_set_pin(UART_PORT, MASTER_UART_TX_GPIO, MASTER_UART_RX_GPIO, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));

    ESP_ERROR_CHECK(uart_driver_install(UART_PORT, 4096, 1024, 0, NULL, 0));

    // create queue
    uart_tx_queue = xQueueCreate(10, 6); // store BSSID frames
    assert(uart_tx_queue);

    // start UART TX task
    xTaskCreate(uart_tx_task, "uart_tx_task", 4096, NULL, 6, NULL);
}


static void timer_send_deauth_frame(void *arg)
{
    
    uart_write_bytes(UART_NUM_1, "HELLO", 5);
    // uint8_t *bssid = (uint8_t *)arg;
    // if (!bssid) return;

    // // post BSSID to queue
    // if (uart_tx_queue) {
    //     xQueueSend(uart_tx_queue, bssid, 0);
    // }
}


void attack_method_broadcast(const wifi_ap_record_t *ap_record, unsigned period_sec){
    ESP_LOGI(TAG, "----------------Starting broadcast-----------------");
    if (deauth_timer_handle) {
        ESP_LOGW(TAG, "broadcast already running");
        return;
    }

    g_bssid_heap = malloc(6);
    if (!g_bssid_heap) {
        ESP_LOGE(TAG, "malloc failed");
        return;
    }
    memcpy(g_bssid_heap, ap_record->bssid, 6);

    const esp_timer_create_args_t deauth_timer_args = {
        .callback = &timer_send_deauth_frame,
        .arg = (void *) g_bssid_heap,
        .name = "bssid_sender"
    };
    ESP_ERROR_CHECK(esp_timer_create(&deauth_timer_args, &deauth_timer_handle));
    ESP_ERROR_CHECK(esp_timer_start_periodic(deauth_timer_handle, period_sec * 1000000));
}

void attack_method_broadcast_stop(){
    if (deauth_timer_handle) {
        ESP_ERROR_CHECK(esp_timer_stop(deauth_timer_handle));
        ESP_ERROR_CHECK(esp_timer_delete(deauth_timer_handle));
        deauth_timer_handle = NULL;
    }
    if (g_bssid_heap) {
        free(g_bssid_heap);
        g_bssid_heap = NULL;
    }
}