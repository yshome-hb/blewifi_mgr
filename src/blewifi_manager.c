#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <cjson/cJSON.h>
#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"
#include "lib/l2cap.h"
#include "lib/uuid.h"
#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/timeout.h"
#include "ble_advertise.h"
#include "gatt_server.h"
#include "network_util.h"


#define WIFI_SSID_CMD 		"nmcli device status | grep wifi | awk '{print $4}'"
#define WIFI_STATUS_CMD 	"nmcli device status | grep wifi | awk '{print $3}'"
#define WIFI_CONNECT_CMD 	"../wifi_config.sh %s %s"


enum net_con_status_e {
	CON_OFFLINE,
	CON_LOCAL,
	CON_CLOUD,
};

struct net_mgr_info{
	sem_t sem;

	int status;
	char ssid[128];
	char pwd[128];
};

const static char *net_status_str[] = {"offline", "local", "cloud"};
static struct net_mgr_info net_info;


static int32_t myexec(const char *cmd, char *res, int32_t len)
{
	int ret = 0;
	FILE *p = popen(cmd, "r");
	if(!p)
		return -1;

	if(fgets(res, len, p) == NULL){
		ret = -1;
	}

	pclose(p);
	return ret;
}


void gatt_recv_bwifi_ssid_callback(char *str, int *len)
{
	cJSON *jroot = NULL;
	cJSON *jssid = NULL;
	cJSON *jpwd = NULL;

	jroot = cJSON_Parse(str);
	if(jroot ==  NULL){
		fprintf(stderr, "recv invalid ssid message: %s\n", str);
		return;
	}

	jssid = cJSON_GetObjectItem(jroot, "ssid");
	if(jssid ==  NULL){
		fprintf(stderr, "recv message have no ssid: %s\n", str);
		goto end;
	}

	jpwd = cJSON_GetObjectItem(jroot, "password");
	if(jpwd ==  NULL){
		fprintf(stderr, "recv message have no password: %s\n", str);
		goto end;
	}

	memset(net_info.ssid, 0, sizeof(net_info.ssid));
	memset(net_info.pwd, 0, sizeof(net_info.pwd));
	strncpy(net_info.ssid, jssid->valuestring, sizeof(net_info.ssid) - 1);
	strncpy(net_info.pwd, jpwd->valuestring, sizeof(net_info.pwd) - 1);

	snprintf(str, *len, "{\"ssid\": \"%s\"}", net_info.ssid);
	*len = strlen(str);

	sem_post(&net_info.sem);

end:
	cJSON_Delete(jroot);
}


static void ble_advertise_complete(int code)
{
	if(code == 0){
		fprintf(stderr, "set advertise complete\n");
	}else{
		mainloop_quit();
	}
}


static void signal_cb(int signum, void *user_data)
{
	switch (signum) {
	case SIGINT:
	case SIGTERM:
		mainloop_quit();
		break;
	default:
		break;
	}
}


static void* net_process_thread(void *arg)
{
	struct net_mgr_info *info = (struct net_mgr_info *)arg;
	struct timespec ts = {0};
	int net_status = CON_OFFLINE;
	char res_str[256];

	if(myexec(WIFI_SSID_CMD, res_str, sizeof(res_str)) == 0){
		strncpy(info->ssid, res_str, sizeof(info->ssid) - 1);
	}

	if(myexec(WIFI_STATUS_CMD, res_str, sizeof(res_str)) == 0){
		if(strncmp(res_str, "connected", 9) == 0)
			net_status = CON_OFFLINE;
	}

	info->status = net_status;
	snprintf(res_str, sizeof(res_str), "{\"ssid\": \"%s\"}", info->ssid);
	gatt_server_set_info(res_str, net_status_str[info->status]);

	while(1){
		
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 1;

		if(sem_timedwait(&info->sem, &ts) == 0){
			if(strlen(info->ssid) != 0 && strlen(info->pwd) != 0){
				char cmd_str[512];
				snprintf(cmd_str, sizeof(cmd_str), WIFI_CONNECT_CMD, info->ssid, info->pwd);
				if(myexec(cmd_str, res_str, sizeof(res_str)) != 0){
					fprintf(stderr, "wifi connet cmd execute failed!\n");
				}
			}
		}
		
		if(myexec(WIFI_STATUS_CMD, res_str, sizeof(res_str)) != 0){
			fprintf(stderr, "wifi status cmd execute failed!\n");
			continue;
		}

		if(strncmp(res_str, "disconnected", 12) == 0){
			
			fprintf(stderr, "wifi disconneted\n");
			net_status = CON_OFFLINE;
	
			if(strlen(info->ssid) != 0 && strlen(info->pwd) != 0){
				char cmd_str[512];
				snprintf(cmd_str, sizeof(cmd_str), WIFI_CONNECT_CMD, info->ssid, info->pwd);
				if(myexec(cmd_str, res_str, sizeof(res_str)) != 0){
					fprintf(stderr, "wifi connet cmd execute failed!\n");
				}
			}
		}else if(strncmp(res_str, "connected", 9) == 0){
			if(net_if_status("tun0") > 0){
				fprintf(stderr, "connect to cloud\n");
				net_status = CON_CLOUD;
			}else{
				fprintf(stderr, "connect to wifi\n");
				net_status = CON_LOCAL;			
			}
		}

		if(net_status != info->status){
			info->status = net_status;
			gatt_update_bwifi_status(net_status_str[info->status], strlen(net_status_str[info->status]));
		}
	}

	pthread_exit(NULL);
}


int main(int argc, char *argv[])
{
	pthread_t net_tid;
	int sec = BT_SECURITY_LOW;
	sigset_t mask;
	char bt_name[26] = {0};
	uint8_t bt_mac[6] = {0};

	if(sem_init(&net_info.sem, 0, 0) < 0){
        fprintf(stderr, "net semaphore init failed!\n");
		return EXIT_FAILURE;
	}

	mainloop_init();

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);

	mainloop_set_signal(&mask, signal_cb, NULL, NULL);
	
	net_if_mac("wlan0", bt_mac);
	snprintf(bt_name, sizeof(bt_name), "RocKontrol-RDU_%02X%02X", bt_mac[1], bt_mac[0]);

	ble_advertise_init(0, bt_name, bt_mac, ble_advertise_complete);
	gatt_server_init(BDADDR_ANY, sec, bt_name);

	printf("Running GATT server\n");

    if (pthread_create(&net_tid, NULL, (void *)net_process_thread, (void *)&net_info) != 0) {
        fprintf(stderr, "net proc thread create failed!\n");
		return EXIT_FAILURE;
    }

	mainloop_run();

	printf("\n\nShutting down...\n");

	return EXIT_SUCCESS;
}
