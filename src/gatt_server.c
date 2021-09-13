#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/uuid.h"
#include "src/shared/mainloop.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-server.h"
#include "gatt_server.h"


#define UUID_GAP			0x1800
#define UUID_GATT			0x1801
#define UUID_SVC_BWIFI		0xFFA0
#define UUID_CHR_SSID		0xFFA1
#define UUID_CHR_STATUS		0xFFA2

#define ATT_CID 4


struct service_info {
	char *bt_name;
	char *ssid;
	int ssid_len;
	char *status;
	int status_len;
};


struct bwifi_gatt_server{
	int fd;
	struct bt_att *att;
	struct gatt_db *db;
	struct bt_gatt_server *gatt;

	uint16_t gatt_svc_chngd_handle;
	bool svc_chngd_enabled;

	uint16_t bwifi_handle;
	uint16_t bwifi_status_handle;
	bool bwifi_status_notify_enabled;

	struct service_info *info;
};


static struct bwifi_gatt_server *server = NULL;


static void server_destroy(struct bwifi_gatt_server *server)
{
	if(server->gatt) { bt_gatt_server_unref(server->gatt); server->gatt = NULL; }
	if(server->db) { gatt_db_unref(server->db); server->db = NULL; }
	if(server->att) { bt_att_unref(server->att); server->att = NULL; }
	close(server->fd);
}


static void att_disconnect_callback(int err, void *user_data)
{
	struct bwifi_gatt_server *server = user_data;	
	
	printf("Device disconnected: %s\n", strerror(err));

	server_destroy(server);
}


static void gap_device_name_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct bwifi_gatt_server *server = user_data;
	uint8_t error = 0;

	fprintf(stderr,  "GAP Device Name Read called\n");

	if (offset) {
		error = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

done:
	gatt_db_attribute_read_result(attrib, id, error, server->info->bt_name, strlen(server->info->bt_name));
}


static void gap_device_name_ext_prop_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	uint8_t value[2];

	fprintf(stderr,  "Device Name Extended Properties Read called\n");

	value[0] = BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE;
	value[1] = 0;

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}


static void gatt_service_changed_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	fprintf(stderr,  "Service Changed Read called\n");

	gatt_db_attribute_read_result(attrib, id, 0, NULL, 0);
}


static void gatt_svc_chngd_ccc_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct bwifi_gatt_server *server = user_data;
	uint8_t value[2];

	fprintf(stderr,  "Service Changed CCC Read called\n");

	value[0] = server->svc_chngd_enabled ? 0x02 : 0x00;
	value[1] = 0x00;

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}


static void gatt_svc_chngd_ccc_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct bwifi_gatt_server *server = user_data;
	uint8_t ecode = 0;

	fprintf(stderr,  "Service Changed CCC Write called\n");

	if (!value || len != 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (value[0] == 0x00)
		server->svc_chngd_enabled = false;
	else if (value[0] == 0x02)
		server->svc_chngd_enabled = true;
	else
		ecode = 0x80;

	fprintf(stderr,  "Service Changed Enabled: %s\n",
				server->svc_chngd_enabled ? "true" : "false");

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}


static void bwifi_status_ccc_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct bwifi_gatt_server *server = user_data;
	uint8_t value[2];

	value[0] = server->bwifi_status_notify_enabled ? 0x01 : 0x00;
	value[1] = 0x00;

	gatt_db_attribute_read_result(attrib, id, 0, value, sizeof(value));
}


static void bwifi_status_ccc_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct bwifi_gatt_server *server = user_data;
	uint8_t ecode = 0;

	if (!value || len != 2) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	if (value[0] == 0x00)
		server->bwifi_status_notify_enabled = false;
	else if (value[0] == 0x01)
		server->bwifi_status_notify_enabled = true;
	else
		ecode = 0x80;

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}


static void bwifi_status_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct bwifi_gatt_server *server = user_data;
	uint8_t ecode = 0;

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

done:
	gatt_db_attribute_read_result(attrib, id, ecode, server->info->status, server->info->status_len);
}


static void bwifi_ssid_read_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct bwifi_gatt_server *server = user_data;
	uint8_t ecode = 0;

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

done:
	gatt_db_attribute_read_result(attrib, id, ecode, server->info->ssid, server->info->ssid_len);
}


static void bwifi_ssid_write_cb(struct gatt_db_attribute *attrib,
					unsigned int id, uint16_t offset,
					const uint8_t *value, size_t len,
					uint8_t opcode, struct bt_att *att,
					void *user_data)
{
	struct bwifi_gatt_server *server = user_data;
	uint8_t ecode = 0;

	if (!value || !len || len >= 255) {
		ecode = BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN;
		goto done;
	}

	if (offset) {
		ecode = BT_ATT_ERROR_INVALID_OFFSET;
		goto done;
	}

	strncpy(server->info->ssid, value, len);
	server->info->ssid[len] = '\0';
	
	server->info->ssid_len = 255;
	gatt_recv_bwifi_ssid_callback(server->info->ssid, &server->info->ssid_len);

	fprintf(stderr, "server ssid %s\n", server->info->ssid);

done:
	gatt_db_attribute_write_result(attrib, id, ecode);
}


static void populate_gap_service(struct bwifi_gatt_server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *att_service, *chr_appearance;
	uint16_t appearance;

	/* Add the GAP service */
	bt_uuid16_create(&uuid, UUID_GAP);
	att_service = gatt_db_add_service(server->db, &uuid, true, 6);

	/*
	 * Device Name characteristic. Make the value dynamically read and
	 * written via callbacks.
	 */
	bt_uuid16_create(&uuid, GATT_CHARAC_DEVICE_NAME);
	gatt_db_service_add_characteristic(att_service, &uuid,
					BT_ATT_PERM_READ,
					BT_GATT_CHRC_PROP_READ |
					BT_GATT_CHRC_PROP_EXT_PROP,
					gap_device_name_read_cb,
					NULL,
					server);

	bt_uuid16_create(&uuid, GATT_CHARAC_EXT_PROPER_UUID);
	gatt_db_service_add_descriptor(att_service, &uuid, BT_ATT_PERM_READ,
					gap_device_name_ext_prop_read_cb,
					NULL, server);

	/*
	 * Appearance characteristic. Reads and writes should obtain the value
	 * from the database.
	 */
	bt_uuid16_create(&uuid, GATT_CHARAC_APPEARANCE);
	chr_appearance = gatt_db_service_add_characteristic(att_service, &uuid,
							BT_ATT_PERM_READ,
							BT_GATT_CHRC_PROP_READ,
							NULL, NULL, server);

	/*
	 * Write the appearance value to the database, since we're not using a
	 * callback.
	 */
	put_le16(128, &appearance);
	gatt_db_attribute_write(chr_appearance, 0, (void *) &appearance,
							sizeof(appearance),
							BT_ATT_OP_WRITE_REQ,
							NULL, NULL, NULL);

	gatt_db_service_set_active(att_service, true);
}


static void populate_gatt_service(struct bwifi_gatt_server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *att_service, *svc_chngd;

	/* Add the GATT service */
	bt_uuid16_create(&uuid, UUID_GATT);
	att_service = gatt_db_add_service(server->db, &uuid, true, 4);

	bt_uuid16_create(&uuid, GATT_CHARAC_SERVICE_CHANGED);
	svc_chngd = gatt_db_service_add_characteristic(att_service, &uuid,
			BT_ATT_PERM_READ,
			BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_INDICATE,
			gatt_service_changed_cb,
			NULL, server);
	server->gatt_svc_chngd_handle = gatt_db_attribute_get_handle(svc_chngd);

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_service_add_descriptor(att_service, &uuid,
				BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
				gatt_svc_chngd_ccc_read_cb,
				gatt_svc_chngd_ccc_write_cb, server);

	gatt_db_service_set_active(att_service, true);
}


static void populate_bwifi_service(struct bwifi_gatt_server *server)
{
	bt_uuid_t uuid;
	struct gatt_db_attribute *att_service, *att_status;

	bt_uuid16_create(&uuid, UUID_SVC_BWIFI);
	att_service = gatt_db_add_service(server->db, &uuid, true, 8);
	server->bwifi_handle = gatt_db_attribute_get_handle(att_service);

	bt_uuid16_create(&uuid, UUID_CHR_SSID);
	gatt_db_service_add_characteristic(att_service, &uuid,
						BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
						BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_WRITE,
						bwifi_ssid_read_cb, bwifi_ssid_write_cb, server);

	bt_uuid16_create(&uuid, UUID_CHR_STATUS);
	att_status = gatt_db_service_add_characteristic(att_service, &uuid,
						BT_ATT_PERM_READ,
						BT_GATT_CHRC_PROP_READ | BT_GATT_CHRC_PROP_NOTIFY,
						bwifi_status_read_cb, NULL, server);
	server->bwifi_status_handle = gatt_db_attribute_get_handle(att_status);

	bt_uuid16_create(&uuid, GATT_CLIENT_CHARAC_CFG_UUID);
	gatt_db_service_add_descriptor(att_service, &uuid,
					BT_ATT_PERM_READ | BT_ATT_PERM_WRITE,
					bwifi_status_ccc_read_cb,
					bwifi_status_ccc_write_cb, server);

	gatt_db_service_set_active(att_service, true);
}


static int server_create(int fd, struct bwifi_gatt_server *server)
{
	server->att = bt_att_new(fd, false);
	if (!server->att) {
		fprintf(stderr, "Failed to initialze ATT transport layer\n");
		goto fail;
	}

	if (!bt_att_set_close_on_unref(server->att, true)) {
		fprintf(stderr, "Failed to set up ATT transport layer\n");
		goto fail;
	}

	if (!bt_att_register_disconnect(server->att, att_disconnect_callback, server,
									NULL)) {
		fprintf(stderr, "Failed to set ATT disconnect handler\n");
		goto fail;
	}

	server->fd = fd;
	server->db = gatt_db_new();
	if (!server->db) {
		fprintf(stderr, "Failed to create GATT database\n");
		goto fail;
	}

	server->gatt = bt_gatt_server_new(server->db, server->att, 0);
	if (!server->gatt) {
		fprintf(stderr, "Failed to create GATT server\n");
		goto fail;
	}

	populate_gap_service(server);
	populate_gatt_service(server);
	populate_bwifi_service(server);

	return 0;

fail:
	if(server->gatt) { bt_gatt_server_unref(server->gatt); server->gatt = NULL; }
	if(server->db) { gatt_db_unref(server->db); server->db = NULL; }
	if(server->att) { bt_att_unref(server->att); server->att = NULL; }
	close(fd);

	return -1;
}


static void att_connect_callback(int fd, uint32_t events, void *user_data)
{
	struct sockaddr_l2 addr;
	socklen_t addrlen;
	int new_fd;

	if (events & (EPOLLERR | EPOLLHUP)) {
		mainloop_remove_fd(fd);
		return;
	}

	memset(&addr, 0, sizeof(addr));
	addrlen = sizeof(addr);
	new_fd = accept(fd, (struct sockaddr *) &addr, &addrlen);
	if (new_fd < 0) {
		fprintf(stderr, "Failed to accept new ATT connection: %m\n");
		return;
	}

	{
		char ba[18];
		ba2str(&addr.l2_bdaddr, ba);
		printf("Connect from %s\n", ba);
	}

	if (server_create(new_fd, (struct bwifi_gatt_server *)user_data) < 0) {
		close(new_fd);
	}
}


int gatt_server_init(bdaddr_t *src, int sec, const char *name)
{
	int l2cap_fd;
	struct sockaddr_l2 srcaddr;
	struct bt_security btsec;
	struct service_info *svc_info = NULL;

	l2cap_fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
	if (l2cap_fd < 0) {
		fprintf(stderr, "Failed to create L2CAP socket\n");
		return -1;
	}

	/* Set up source address */
	memset(&srcaddr, 0, sizeof(srcaddr));
	srcaddr.l2_family = AF_BLUETOOTH;
	srcaddr.l2_cid = htobs(ATT_CID);
	srcaddr.l2_bdaddr_type = BDADDR_LE_RANDOM;
	bacpy(&srcaddr.l2_bdaddr, src);

	if (bind(l2cap_fd, (struct sockaddr *) &srcaddr, sizeof(srcaddr)) < 0) {
		fprintf(stderr, "Failed to bind L2CAP socket\n");
		goto fail;
	}

	/* Set the security level */
	memset(&btsec, 0, sizeof(btsec));
	btsec.level = sec;
	if (setsockopt(l2cap_fd, SOL_BLUETOOTH, BT_SECURITY, &btsec, sizeof(btsec)) != 0) {
		fprintf(stderr, "Failed to set L2CAP security level\n");
		goto fail;
	}

	if (listen(l2cap_fd, 1) < 0) {
		fprintf(stderr, "Listening on socket failed\n");
		goto fail;
	}

	svc_info = new0(struct service_info, 1);
	if (!svc_info) {
		fprintf(stderr, "Failed to allocate memory for service info\n");
		goto fail;
	}

	svc_info->bt_name = new0(char, 255);
	if (!svc_info->bt_name) {
		fprintf(stderr, "Failed to allocate memory for bt name\n");
		goto fail;
	}

	svc_info->ssid = new0(char, 255);
	if (!svc_info->ssid) {
		fprintf(stderr, "Failed to allocate memory for wifi ssid\n");
		goto fail;
	}

	svc_info->status = new0(char, 255);
	if (!svc_info->status) {
		fprintf(stderr, "Failed to allocate memory for wifi status\n");
		goto fail;
	}

	server = new0(struct bwifi_gatt_server, 1);
	if (!server) {
		fprintf(stderr, "Failed to allocate memory for gatt server\n");
		goto fail;
	}

	server->info = svc_info;
	strncpy(server->info->bt_name, name, 254);
	printf("Started listening on ATT channel. Waiting for connections\n");

	mainloop_add_fd(l2cap_fd, EPOLLIN, att_connect_callback, (void *)server, NULL);

	return l2cap_fd;

fail:
	if(svc_info->status) free(svc_info->status);
	if(svc_info->ssid) free(svc_info->ssid);
	if(svc_info->bt_name) free(svc_info->bt_name);	
	if(svc_info) free(svc_info);
	close(l2cap_fd);
	return -1;
}


void gatt_server_set_info(const char *ssid, const char *status)
{
	if(server == NULL)
		return;

	if(ssid){
		memset(server->info->ssid, 0, 255);
		strncpy(server->info->ssid, ssid, 254);
		server->info->ssid_len = strlen(server->info->ssid);
	}

	if(status){
		memset(server->info->status, 0, 255);
		strncpy(server->info->status, status, 254);
		server->info->status_len = strlen(server->info->status);
	}
}


void gatt_update_bwifi_status(const char *str, int len)
{
	if(server == NULL)
		return;
	
	strncpy(server->info->status, str, len);
	server->info->status[len] = '\0';
	server->info->status_len = len;

	if(!server->gatt){
		fprintf(stderr, "gatt server not connected\n");
		return;
	}

	if( !server->bwifi_status_notify_enabled){
		fprintf(stderr, "status notify not enabled\n");
		return;
	}

	if (!bt_gatt_server_send_notification(server->gatt, server->bwifi_status_handle,
										server->info->status, server->info->status_len))
		fprintf(stderr, "Failed to initiate notification\n");
}

