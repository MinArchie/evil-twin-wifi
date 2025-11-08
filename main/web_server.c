
#include "web_server.h"
#include "wifi_handler.h"
#include "project_types.h"
#include "tflite_handler.h"
#include "esp_event.h"
#include <string.h>
#include <stdlib.h>     // For malloc/free
#include <stdio.h>      // For sscanf
#include <inttypes.h>   // <-- FIX: Added for portable integer formatting (PRId32)
#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wifi_controller.h"

static const char* TAG = "WEB_SERVER";

ESP_EVENT_DEFINE_BASE(WEB_EVENTS);

// --- Helper Functions (from .ino) ---

// Replaces getRiskColor()
static const char* get_risk_color(const char* risk) {
    if (strcmp(risk, "Good") == 0) return "#28a745";   // Green
    if (strcmp(risk, "Medium") == 0) return "#ffc107"; // Yellow
    if (strcmp(risk, "Risky") == 0) return "#dc3545";  // Red
    return "#6c757d";                                // Gray
}

// Replaces classifyNetwork()
// It now takes the C-struct
static const char* classify_network(const struct ScannedNetwork* net) {
    float auth = (float)net->authmode;
    float min_rssi = -90.0;
    float max_rssi = -30.0;
    float rssi = ((float)net->rssi - min_rssi) / (max_rssi - min_rssi);
    if (rssi < 0.0) rssi = 0.0;
    if (rssi > 1.0) rssi = 1.0;
    float hidden = (float)net->hidden;

    // Call our TFLM C-wrapper function
    return classify_network_from_features(auth, rssi, hidden);
}

// --- HTML Sending Functions ---

// This function replaces your scanNetworksHTML()
// It's much more complex because we can't build one giant String.
// We scan, then build and send the HTML line by line.
static esp_err_t send_scan_table(httpd_req_t *req) {
    // 1. Send the CSS styles first
    const char* style_chunk =
        "<style>"
        "table { border-collapse: collapse; width: 100%; font-family: sans-serif; }"
        "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }"
        "tr:nth-child(even) { background-color: #f2f2f2; }"
        "th { background-color: #007bff; color: white; }"
        ".risk-cell { color: white; font-weight: bold; text-align: center; }"
        ".view-btn { background-color: #17a2b8; color: white!important; padding: 5px 10px; border: none; border-radius: 4px; font-size: 12px; cursor: pointer; text-decoration: none; display: inline-block; }"
        ".view-btn:hover { background-color: #138496; }"
        ".deauth-btn { background-color: #dc3545; color: white!important; padding: 5px 10px; border: none; border-radius: 4px; font-size: 12px; cursor: pointer; text-decoration: none; display: inline-block; }"
        ".deauth-btn:hover { background-color: #c82333; }"
        "</style>";
    httpd_resp_send_chunk(req, style_chunk, HTTPD_RESP_USE_STRLEN);

    // 2. Perform the Wi-Fi Scan
    ESP_LOGI(TAG, "Starting network scan...");
    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true
    };
    // Start scan (blocking call)
    if (esp_wifi_scan_start(&scan_config, true) != ESP_OK) {
        httpd_resp_send_chunk(req, "<p>Scan failed</p>", HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Scan complete.");

    uint16_t num_aps = 0;
    esp_wifi_scan_get_ap_num(&num_aps);
    if (num_aps == 0) {
        httpd_resp_send_chunk(req, "<p>No networks found.</p>", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    // Allocate memory to hold all the scan results
    wifi_ap_record_t* ap_list = (wifi_ap_record_t*)malloc(sizeof(wifi_ap_record_t) * num_aps);
    if (ap_list == NULL) {
        httpd_resp_send_chunk(req, "<p>Failed to allocate memory for scan results</p>", HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }

    // Get the results
    ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&num_aps, ap_list));

    wifictl_store_scan_results(ap_list, num_aps);
    // 3. Send the table header
    const char* table_header = 
        "<table>"
        "<tr><th>SSID</th><th>BSSID</th><th>RSSI (dBm)</th><th>Channel</th><th>Hidden</th><th>Auth</th><th>Risk Level</th><th>Action</th></tr>";
    httpd_resp_send_chunk(req, table_header, HTTPD_RESP_USE_STRLEN);

    // 4. Loop through results and send one row at a time
    char line_buffer[1024]; // Buffer to build one <tr>...</tr> line
    for (int i = 0; i < num_aps; i++) {
        struct ScannedNetwork net;
        
        // Copy data from the AP record to our C-struct
        strncpy(net.ssid, (char*)ap_list[i].ssid, 32);
        net.ssid[32] = '\0'; // Ensure null termination
        snprintf(net.bssid_str, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
                 ap_list[i].bssid[0], ap_list[i].bssid[1], ap_list[i].bssid[2],
                 ap_list[i].bssid[3], ap_list[i].bssid[4], ap_list[i].bssid[5]);
        net.rssi = ap_list[i].rssi;
        net.channel = ap_list[i].primary;
        net.hidden = (strlen(net.ssid) == 0);
        net.authmode = ap_list[i].authmode;
        strncpy(net.authString, get_auth_mode_name(net.authmode), 31);
        net.authString[31] = '\0';

        // Get classification
        const char* riskLevel = classify_network(&net);
        const char* riskColor = get_risk_color(riskLevel);

        // Build URLs
        char cloneUrl[256];
        // <-- FIX: Changed %d to %"PRId32" for net.channel (it's an int32_t)
        snprintf(cloneUrl, sizeof(cloneUrl), "/clone?ssid=%s&ch=%" PRId32 "&auth=%d",
                 net.ssid, net.channel, net.authmode);
        char deauthUrl[256];
        // <-- FIX: Changed %d to %"PRId32" for net.channel
        snprintf(deauthUrl, sizeof(deauthUrl), "/deauth?bssid=%s&sta=broadcast&ch=%" PRId32 "",
                 net.bssid_str, net.channel);

        // Build the final HTML table row
        snprintf(line_buffer, sizeof(line_buffer),
            "<tr>"
            "<td>%s</td>"
            "<td>%s</td>"
            "<td>%" PRId32 "</td>" // <-- FIX: Changed %d to %"PRId32" for net.rssi
            "<td>%" PRId32 "</td>" // <-- FIX: Changed %d to %"PRId32" for net.channel
            "<td>%s</td>"
            "<td>%s</td>"
            "<td class='risk-cell' style='background-color:%s;'>%s</td>"
            "<td>"
            "<a href='%s' class='view-btn' style='margin-right:5px;'>View</a>"
            "<a href='%s' class='deauth-btn' onclick='return confirm(\"Send broadcast deauth to %s?\");'>Deauth</a>"
            "</td>"
            "</tr>",
            net.ssid, net.bssid_str, net.rssi, net.channel,
            net.hidden ? "Yes" : "No", net.authString,
            riskColor, riskLevel,
            cloneUrl, deauthUrl, net.ssid
        );
        
        // Send the line
        httpd_resp_send_chunk(req, line_buffer, HTTPD_RESP_USE_STRLEN);
    }

    // 5. Clean up and send table footer
    free(ap_list);
    httpd_resp_send_chunk(req, "</table>", HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}

// --- HTTP Request Handlers ---

// Replaces handleRoot()
static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    const char* html =
        "<html><head><title>ESP32 Wi-Fi Hub</title>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<style>body { font-family: sans-serif; padding: 20px; text-align: center; }"
        "h1 { color: #333; }"
        "button { background-color: #007bff; color: white; padding: 20px 30px; border: none; border-radius: 5px; font-size: 18px; cursor: pointer; width: 300px; margin: 10px; }"
        "button:hover { background-color: #0056b3; }"
        ".btn-config { background-color: #28a745; }"
        ".btn-config:hover { background-color: #218838; }"
        "</style></head><body>"
        "<h1>ESP32 Wi-Fi Hub</h1>"
        "<p><a href='/scan'><button>Scan & Classify Networks</button></a></p>"
        "<p><a href='/hotspot'><button class='btn-config'>Configure This Hotspot</button></a></p>"
        "</body></html>";
    httpd_resp_send(req, html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// Replaces handleScan()
static esp_err_t scan_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    // Send the HTML in chunks
    const char* part1 = 
        "<html><head><meta http-equiv='refresh' content='10'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<style>body { font-family: sans-serif; padding: 10px; }"
        "button { background-color: #6c757d; color: white; padding: 10px 15px; border: none; border-radius: 5px; font-size: 14px; cursor: pointer; text-decoration: none; }"
        "button:hover { background-color: #5a6268; }"
        "</style></head><body>"
        "<h2>Available Wi-Fi Networks (Refreshing...)</h2>";
    httpd_resp_send_chunk(req, part1, HTTPD_RESP_USE_STRLEN);

    // Send the dynamic table
    send_scan_table(req);

    // Send the footer
    const char* part2 =
        "<br><a href='/'><button>Back to Menu</button></a>"
        "</body></html>";
    httpd_resp_send_chunk(req, part2, HTTPD_RESP_USE_STRLEN);

    // Send the final empty chunk to finish the response
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

// Replaces handleHotspotPage()
static esp_err_t hotspot_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    
    // We must build the HTML dynamically to show current settings
    char* html_buffer = malloc(4096); // Allocate a large buffer
    if (html_buffer == NULL) return ESP_FAIL;

    // Use snprintf to build the HTML string
    snprintf(html_buffer, 4096,
        "<html><head><title>ESP32 Hotspot Control</title>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<style>body { font-family: sans-serif; padding: 20px; }"
        "form { border: 1px solid #ccc; padding: 15px; border-radius: 5px; }"
        // <-- FIX: Escaped % with %%
        "input, select { width: 100%%; padding: 8px; margin-bottom: 10px; box-sizing: border-box; }"
        "input[type=submit] { background-color: #28a745; color: white; font-size: 16px; cursor: pointer; }"
        "input[type=submit]:hover { background-color: #218838; }"
        "button { background-color: #6c757d; color: white; padding: 10px 15px; border: none; border-radius: 5px; font-size: 14px; cursor: pointer; text-decoration: none; display: inline-block; }"
        "button:hover { background-color: #5a6268; }"
        "</style></head><body>"
        "<h2>ESP32 Wi-Fi Hotspot Control</h2>"
        "<form action='/update' method='POST'>"
        "SSID: <input name='ssid' value='%s'><br><br>"
        "Password: <input name='password' value='%s' placeholder='Leave blank for open network'><br><br>"
        // <-- FIX: Changed %d to %"PRId32" for g_hotspotConfig.channel
        "Channel: <input type='number' name='channel' value='%" PRId32 "' min='1' max='13'><br><br>"
        "Hidden SSID: <input type='checkbox' name='hidden' %s style='width:auto; margin-bottom:0;'><br><br>"
        "Auth Mode: <select name='authmode'>"
        "<option value='0' %s>Open (No Password)</option>"
        "<option value='1' %s>WPA2-PSK</option>"
        "</select><br><br>"
        "<input type='submit' value='Apply Settings'>"
        "</form><br><hr>"
        "<h3>Current Hotspot Info</h3>"
        "<p><b>SSID:</b> %s<br>"
        "<b>BSSID:</b> %s<br>"
        // <-- FIX: Changed %d to %"PRId32" for g_hotspotConfig.channel
        "<b>Channel:</b> %" PRId32 "<br>"
        "<b>Hidden:</b> %s<br>"
        "<b>Auth Mode:</b> %s<br>"
        "<b>Password:</b> %s</p>"
        "<br><a href='/'><button>Back to Menu</button></a>"
        "</body></html>",
        g_hotspotConfig.ssid,
        g_hotspotConfig.password,
        g_hotspotConfig.channel,
        g_hotspotConfig.hidden ? "checked" : "",
        g_hotspotConfig.authmode == 0 ? "selected" : "",
        g_hotspotConfig.authmode == 1 ? "selected" : "",
        g_hotspotConfig.ssid,
        g_hotspotConfig.bssid_str,
        g_hotspotConfig.channel,
        g_hotspotConfig.hidden ? "Yes" : "No",
        g_hotspotConfig.authString,
        (g_hotspotConfig.authmode == 0 ? "(none)" : g_hotspotConfig.password)
    );

    httpd_resp_send(req, html_buffer, HTTPD_RESP_USE_STRLEN);
    free(html_buffer); // Don't forget to free the memory!
    return ESP_OK;
}

static esp_err_t hotspot_post_handler(httpd_req_t *req)
{
    char buf[512];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    ESP_LOGI(TAG, "Got hotspot update data: %s", buf);

    static wifi_ap_record_t ap_record = {0};
    static attack_config_t attack_config = {0};
    attack_config.ap_record = &ap_record;

    char param_buf[64];

    if (httpd_query_key_value(buf, "ssid", param_buf, sizeof(param_buf)) == ESP_OK) {
        strncpy((char *)ap_record.ssid, param_buf, sizeof(ap_record.ssid) - 1);
    }

    if (httpd_query_key_value(buf, "password", param_buf, sizeof(param_buf)) == ESP_OK) {
        strncpy(attack_config.password, param_buf, sizeof(attack_config.password) - 1);
    } else {
        strcpy(attack_config.password, "dummypassword");
    }

    if (httpd_query_key_value(buf, "channel", param_buf, sizeof(param_buf)) == ESP_OK)
        ap_record.primary = atoi(param_buf);
    else
        ap_record.primary = 6;

    if (httpd_query_key_value(buf, "authmode", param_buf, sizeof(param_buf)) == ESP_OK)
        ap_record.authmode = atoi(param_buf);
    else
        ap_record.authmode = WIFI_AUTH_WPA2_PSK;

    attack_config.hidden = (httpd_query_key_value(buf, "hidden", param_buf, sizeof(param_buf)) == ESP_OK);

    ESP_LOGI(TAG, "Hotspot config → SSID: %s | Channel: %d | Hidden: %s | Auth: %d",
             ap_record.ssid, ap_record.primary,
             attack_config.hidden ? "Yes" : "No", ap_record.authmode);

    attack_method_rogueap(&attack_config, 1);

    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/hotspot");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}


// Replaces handleClone()
static esp_err_t clone_get_handler(httpd_req_t *req)
{
    size_t buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len <= 1) return ESP_FAIL; // No query

    char* buf = malloc(buf_len);
    if (httpd_req_get_url_query_str(req, buf, buf_len) != ESP_OK) {
        free(buf);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Got clone data: %s", buf);

    char param_buf[64];
    // Parse SSID
    if (httpd_query_key_value(buf, "ssid", param_buf, sizeof(param_buf)) == ESP_OK) {
        strncpy(g_hotspotConfig.ssid, param_buf, sizeof(g_hotspotConfig.ssid) - 1);
    }
    // Parse Channel
    if (httpd_query_key_value(buf, "ch", param_buf, sizeof(param_buf)) == ESP_OK) {
        g_hotspotConfig.channel = atoi(param_buf);
    }
    // Parse Auth
    if (httpd_query_key_value(buf, "auth", param_buf, sizeof(param_buf)) == ESP_OK) {
        int scannedAuth = atoi(param_buf);
        if (scannedAuth == WIFI_AUTH_OPEN) {
            g_hotspotConfig.authmode = 0;
            strncpy(g_hotspotConfig.authString, "Open", sizeof(g_hotspotConfig.authString) - 1);
            memset(g_hotspotConfig.password, 0, sizeof(g_hotspotConfig.password));
        } else {
            g_hotspotConfig.authmode = 1;
            strncpy(g_hotspotConfig.authString, "WPA2-PSK", sizeof(g_hotspotConfig.authString) - 1);
            // We keep the old password, or you could set a default
        }
    }

    free(buf);

    // Apply the new settings (this will also restart the AP)
    //start_hotspot(); // Not needed, redirect to /hotspot which shows settings, user must click "Apply"

    // Redirect to the hotspot page to show the "cloned" settings
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/hotspot");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t deauth_get_handler(httpd_req_t *req)
{
    size_t buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len <= 1) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing parameters");
        return ESP_FAIL;
    }

    char* buf = malloc(buf_len);
    if (buf == NULL) return ESP_FAIL;
    if (httpd_req_get_url_query_str(req, buf, buf_len) != ESP_OK) {
        free(buf);
        return ESP_FAIL;
    }

    char bssid_str[32] = {0};
    char sta_str[32] = {0};
    char ch_str[8] = {0};

    if (httpd_query_key_value(buf, "bssid", bssid_str, sizeof(bssid_str)) != ESP_OK) {
        free(buf);
        return ESP_FAIL;
    }
    // optional params - not used for ap lookup but kept for completeness
    httpd_query_key_value(buf, "sta", sta_str, sizeof(sta_str));
    httpd_query_key_value(buf, "ch", ch_str, sizeof(ch_str));
    free(buf);

    // Convert BSSID string "AA:BB:CC:DD:EE:FF" to bytes
    uint8_t bssid[6] = {0};
    int parsed = sscanf(bssid_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &bssid[0], &bssid[1], &bssid[2],
                        &bssid[3], &bssid[4], &bssid[5]);
    if (parsed != 6) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad BSSID format");
        return ESP_FAIL;
    }

    attack_request_t attack_request = {0};
    memcpy(attack_request.bssid, bssid, 6);
    // you may decide default values for type/method/timeout or parse them from query too
    attack_request.type = ATTACK_TYPE_DOS;   // example default, adapt as needed
    attack_request.method = ATTACK_DOS_METHOD_BROADCAST; // default method
    attack_request.timeout = 10; // seconds

    // Post event to the wifi handler
    esp_err_t err = esp_event_post(WEB_EVENTS, WEB_EVENT_DEAUTH_REQUEST,
                                  &attack_request, sizeof(attack_request_t), portMAX_DELAY);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to post deauth event");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to initiate deauth");
        return ESP_FAIL;
    }

    // immediate response
    char msg_buf[256];
    snprintf(msg_buf, sizeof(msg_buf),
             "<html><body style='font-family: sans-serif;'>"
             "Deauth attack posted for BSSID: %s"
             "<br><br><a href='/scan'>Back to Scan</a></body></html>",
             bssid_str);
    httpd_resp_send(req, msg_buf, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// --- Server Start/Stop ---

// This replaces all your server.on() calls
httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true; // Helps with freeing resources

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Registering URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");

        // httpd_uri_t is a struct that links a URL to a function
        httpd_uri_t root = {
            .uri       = "/",
            .method    = HTTP_GET,
            .handler   = root_get_handler,
            .user_ctx  = NULL
        };
        httpd_register_uri_handler(server, &root);

        httpd_uri_t scan = {
            .uri       = "/scan",
            .method    = HTTP_GET,
            .handler   = scan_get_handler,
            .user_ctx  = NULL
        };
        httpd_register_uri_handler(server, &scan);

        httpd_uri_t hotspot_get = {
            .uri       = "/hotspot",
            .method    = HTTP_GET,
            .handler   = hotspot_get_handler,
            .user_ctx  = NULL
        };
        httpd_register_uri_handler(server, &hotspot_get);
        
        httpd_uri_t hotspot_post = {
            .uri       = "/update",
            .method    = HTTP_POST,
            .handler   = hotspot_post_handler,
            .user_ctx  = NULL
        };
        httpd_register_uri_handler(server, &hotspot_post);

        httpd_uri_t clone = {
            .uri       = "/clone",
            .method    = HTTP_GET,
            .handler   = clone_get_handler,
            .user_ctx  = NULL
        };
        httpd_register_uri_handler(server, &clone);

        httpd_uri_t deauth = {
            .uri       = "/deauth",
            .method    = HTTP_GET,
            .handler   = deauth_get_handler,
            .user_ctx  = NULL
        };
        httpd_register_uri_handler(server, &deauth);
        
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

void stop_webserver(httpd_handle_t server)
{
    if (server) {
        httpd_stop(server);
    }
}