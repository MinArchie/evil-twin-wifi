idf_component_register(SRCS "sniffer.c" "ap_scanner.c" "wifi_controller.c"
                    INCLUDE_DIRS "interface"
                    REQUIRES esp_wifi)

target_link_libraries(${COMPONENT_LIB} -Wl,-zmuldefs)