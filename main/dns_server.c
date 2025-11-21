#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/ip_addr.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "DNS";
#define DNS_PORT 53

static void dns_server_task(void *param)
{
    const char *ap_ip = (const char *)param;

    int dns_sock = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(DNS_PORT);

    bind(dns_sock, (struct sockaddr *)&server_addr, sizeof(server_addr));

    ESP_LOGI(TAG, "DNS server started");

    uint8_t buf[512];
    struct sockaddr_in client;
    socklen_t client_len = sizeof(client);

    ip4_addr_t resolved_ip;
    ip4addr_aton(ap_ip, &resolved_ip);

    while (1) {
        int len = recvfrom(dns_sock, buf, sizeof(buf), 0,
                           (struct sockaddr *)&client, &client_len);

        if (len > 0) {
            buf[2] |= 0x80;
            buf[3] |= 0x80;
            buf[7] = 1;

            uint8_t *answer = buf + len;
            answer[0] = 0xC0;
            answer[1] = 0x0C;
            answer[2] = 0x00;
            answer[3] = 0x01;
            answer[4] = 0x00;
            answer[5] = 0x01;
            answer[6] = 0x00;
            answer[7] = 0x00;
            answer[10] = 0x00;
            answer[11] = 0x04;

            memcpy(answer + 12, &resolved_ip.addr, 4);
            sendto(dns_sock, buf, len + 16, 0,
                   (struct sockaddr *)&client, client_len);
        }

        vTaskDelay(1);  // yield CPU
    }
}

void start_dns_server(const char *ap_ip)
{
    xTaskCreate(dns_server_task, "dns_server", 4096, strdup(ap_ip), 5, NULL);
}
