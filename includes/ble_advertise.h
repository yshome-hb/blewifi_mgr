#ifndef _BLE_ADVERTISE_H_
#define _BLE_ADVERTISE_H_

#include <stdint.h>

typedef void (* ble_advertise_callback)(int);

int ble_advertise_init(uint16_t index, const char *name, const uint8_t *addr, ble_advertise_callback cb);


#endif
