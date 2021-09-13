#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "lib/bluetooth.h"
#include "lib/mgmt.h"
#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/mgmt.h"
#include "ble_advertise.h"


struct adv_mgr_info{
	uint16_t index;
	struct mgmt *mgmt;
	uint8_t static_addr[6];
	char bt_name[260];
	ble_advertise_callback complete_cb;
};


static void ble_advertise_exit(struct adv_mgr_info *info, int code)
{
	info->complete_cb(code);
	mgmt_unref(info->mgmt);
	free(info);
}


static void set_advertise_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	struct adv_mgr_info *info = (struct adv_mgr_info *)user_data;	
	
	if (status) {
		fprintf(stderr, "set advertise failed: %s\n", mgmt_errstr(status));
		ble_advertise_exit(info, -1);
	}

	ble_advertise_exit(info, 0);
}


static void add_advertising(struct adv_mgr_info *info)
{
	struct mgmt_cp_add_advertising *add_cp;
	struct mgmt_cp_remove_advertising rm_cp;
	void *buf;
	size_t add_len;

	add_len = sizeof(*add_cp) + strlen(info->bt_name) + 6;
	add_cp = malloc0(add_len);
	if(!add_cp)
		return;

	memset(add_cp, 0, add_len);
	add_cp->instance = 1;
	add_cp->flags = cpu_to_le32(MGMT_ADV_FLAG_CONNECTABLE | MGMT_ADV_FLAG_DISCOV | MGMT_ADV_FLAG_MANAGED_FLAGS);
	add_cp->duration = cpu_to_le16(0);
	add_cp->timeout = cpu_to_le16(0);
	add_cp->adv_data_len = 6 + strlen(info->bt_name);
	add_cp->scan_rsp_len = 0;

	add_cp->data[0] = 3;
	add_cp->data[1] = 0x03;
	*(uint16_t *)(add_cp->data + 2) = cpu_to_le16(0xFFA0);
	add_cp->data[4] = strlen(info->bt_name) + 1;
	add_cp->data[5] = 0x09;
	strncpy(add_cp->data + 6, info->bt_name, strlen(info->bt_name));

	rm_cp.instance = 1;
	mgmt_send(info->mgmt, MGMT_OP_REMOVE_ADVERTISING, info->index, sizeof(rm_cp), &rm_cp, 
						NULL, NULL, NULL);

	mgmt_send(info->mgmt, MGMT_OP_ADD_ADVERTISING, info->index, add_len, add_cp, 
						set_advertise_complete, info, NULL);

	free(add_cp);
}


static void read_info_complete(uint8_t status, uint16_t len,
					const void *param, void *user_data)
{
	const struct mgmt_rp_read_info *rp = param;
	struct adv_mgr_info *info = (struct adv_mgr_info *)user_data;
	uint32_t required_settings = MGMT_SETTING_LE;
	uint32_t supported_settings, current_settings;
	uint8_t val;

	if (status) {
		fprintf(stderr, "Reading info for index %u failed: %s\n",
							info->index, mgmt_errstr(status));
		ble_advertise_exit(info, -1);
		return;
	}

	supported_settings = le32_to_cpu(rp->supported_settings);
	current_settings = le32_to_cpu(rp->current_settings);

	if ((supported_settings & required_settings) != required_settings){

		ble_advertise_exit(info, -1);
		return;
	}

	if (current_settings & MGMT_SETTING_POWERED) {
		val = 0x00;
		mgmt_send(info->mgmt, MGMT_OP_SET_POWERED, info->index, 1, &val,
							NULL, NULL, NULL);
	}

	if (!(current_settings & MGMT_SETTING_LE)) {
		val = 0x01;
		mgmt_send(info->mgmt, MGMT_OP_SET_LE, info->index, 1, &val,
							NULL, NULL, NULL);
	}

	if (current_settings & MGMT_SETTING_BREDR) {
		val = 0x00;
		mgmt_send(info->mgmt, MGMT_OP_SET_BREDR, info->index, 1, &val,
							NULL, NULL, NULL);
	}

	if (!(current_settings & MGMT_SETTING_BONDABLE)) {
		val = 0x01;
		mgmt_send(info->mgmt, MGMT_OP_SET_BONDABLE, info->index, 1, &val,
							NULL, NULL, NULL);
	}

	mgmt_send(info->mgmt, MGMT_OP_SET_STATIC_ADDRESS, info->index, sizeof(info->static_addr), info->static_addr, 
							NULL, NULL, NULL);

	mgmt_send(info->mgmt, MGMT_OP_SET_LOCAL_NAME, info->index, sizeof(info->bt_name), info->bt_name, 
							NULL, NULL, NULL);

	val = 0x01;
	mgmt_send(info->mgmt, MGMT_OP_SET_POWERED, info->index, 1, &val,
							NULL, NULL, NULL);

	add_advertising(info);

	val = 0x01;
	mgmt_send(info->mgmt, MGMT_OP_SET_ADVERTISING, info->index, 1, &val,
						set_advertise_complete, info, NULL);
}


static void read_index_list_complete(uint8_t status, uint16_t len,
									const void *param, void *user_data)
{
	const struct mgmt_rp_read_index_list *rp = param;
	struct adv_mgr_info *info = (struct adv_mgr_info *)user_data;
	uint16_t count;
	int i = 0;

	if (status) {
		fprintf(stderr, "Reading index list failed: %s\n",
						mgmt_errstr(status));
		ble_advertise_exit(info, -1);
		return;
	}

	count = le16_to_cpu(rp->num_controllers);
	if(count < 1){
		fprintf(stderr, "found no controllers\n");
		ble_advertise_exit(info, -1);
		return;		
	}

	for (i = 0; i < count; i++) {
		if(info->index == cpu_to_le16(rp->index[i])){
			break;
		}
	}

	if(i == count){
		fprintf(stderr, "index %u controller isn't exist\n", info->index);
		ble_advertise_exit(info, -1);
		return;			
	}

	mgmt_send(info->mgmt, MGMT_OP_READ_INFO, info->index, 0, NULL,
			read_info_complete, info, NULL);
}


int ble_advertise_init(uint16_t index, const char *name, const uint8_t *addr, ble_advertise_callback cb)
{
	struct adv_mgr_info *adv_info = NULL;
	
	adv_info = new0(struct adv_mgr_info, 1);
	if(!adv_info){
		fprintf(stderr, "Failed to malloc adv_info\n");
		return -1;		
	}

	adv_info->mgmt = mgmt_new_default();
	if (!adv_info->mgmt) {
		fprintf(stderr, "Failed to open management socket\n");
		free(adv_info);
		return -1;
	}

	adv_info->index = index;
	strncpy(adv_info->bt_name, name, sizeof(adv_info->bt_name) - 1);
	memcpy(adv_info->static_addr, addr, sizeof(adv_info->static_addr));
	adv_info->complete_cb = cb;

	if (!mgmt_send(adv_info->mgmt, MGMT_OP_READ_INDEX_LIST, MGMT_INDEX_NONE, 0, NULL,
				read_index_list_complete, adv_info, NULL)) {
		fprintf(stderr, "Failed to read index list\n");
		mgmt_unref(adv_info->mgmt);
		free(adv_info);
		return -1;
	}

	return 0;
}

