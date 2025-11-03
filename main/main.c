// main/main.c
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "tflite_handler.h"
#include "wifi_handler.h"
#include "web_server.h"
#include "esp_event.h"

static const char* TAG = "MAIN";

void app_main(void)
{
    ESP_LOGI(TAG, "Booting TFLite Wi-Fi Classifier & Hotspot...");

    if (!setup_tflite()) {
        ESP_LOGE(TAG, "Failed to initialize TFLite model!");
        return;
    }
    ESP_LOGI(TAG, "TFLite model initialized.");
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_init_ap_sta();

    start_webserver();

    ESP_LOGI(TAG, "System setup complete. Web server running.");
    
}