set(SOURCES "main.c"
            "wifi_handler.c"
            "web_server.c"
            "uart_deauth.c"
            "dns_server.c")

set(SOURCES_CXX "tflite_handler.cpp")

idf_component_register(SRCS ${SOURCES} ${SOURCES_CXX}
                       INCLUDE_DIRS "."
                       REQUIRES wifi_controller esp_wifi nvs_flash esp_http_server esp_timer spiffs)