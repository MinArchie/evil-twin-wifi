
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define NUM_INPUTS 3
#define NUM_OUTPUTS 3

bool setup_tflite();

const char* classify_network_from_features(float auth, float rssi, float hidden);

#ifdef __cplusplus
}
#endif