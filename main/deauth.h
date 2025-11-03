#ifdef DEAUTH_H
#define DEAUTH_H


typedef struct {
    uint8_t bssid[6];
    uint8_t sta[6];
    int channel;
} deauth_request_t;

typedef enum{
    ATTACK_DOS_METHOD_ROGUE_AP,
    ATTACK_DOS_METHOD_BROADCAST,
    ATTACK_DOS_METHOD_COMBINE_ALL
} attack_dos_methods_t;

void attack_dos_start(attack_config_t *attack_config);
void attack_dos_stop();
#endif