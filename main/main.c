#include "freertos/FreeRTOS.h"

#include "esp_event_loop.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_wifi.h"

#include "nvs_flash.h"
#include "string.h"

#include "wifi_packet_type.h"

esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void *buffer, int len, bool en_sys_seq);

//uint8_t beacon_raw[] = {
//	0x80, 0x00,							// 0-1: Frame Control
//	0x00, 0x00,							// 2-3: Duration
//	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,				// 4-9: Destination address (broadcast)
//	0xba, 0xde, 0xaf, 0xfe, 0x00, 0x06,				// 10-15: Source address
//	0xba, 0xde, 0xaf, 0xfe, 0x00, 0x06,				// 16-21: BSSID
//	0x00, 0x00,							// 22-23: Sequence / fragment number
//	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,			// 24-31: Timestamp (GETS OVERWRITTEN TO 0 BY HARDWARE)
//	0x64, 0x00,							// 32-33: Beacon interval
//	0x31, 0x04,							// 34-35: Capability info
//	0x00, 0x00, /* FILL CONTENT HERE */				// 36-38: SSID parameter set, 0x00:length:content
//	0x01, 0x08, 0x82, 0x84,	0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,	// 39-48: Supported rates
//	0x03, 0x01, 0x01,						// 49-51: DS Parameter set, current channel 1 (= 0x01),
//	0x05, 0x04, 0x01, 0x02, 0x00, 0x00,				// 52-57: Traffic Indication Map
//
//};

uint8_t probePacket[68] = {
	/*  0 - 1  */ 0x40, 0x00,                                       // Type: Probe Request
	/*  2 - 3  */ 0x00, 0x00,                                       // Duration: 0 microseconds
	/*  4 - 9  */ 0xff, 0xff,               0xff, 0xff, 0xff, 0xff, // Destination: Broadcast
	/* 10 - 15 */ 0xAA, 0xAA,               0xAA, 0xAA, 0xAA, 0xAA, // Source: random MAC
	/* 16 - 21 */ 0xff, 0xff,               0xff, 0xff, 0xff, 0xff, // BSS Id: Broadcast
	/* 22 - 23 */ 0x00, 0x00,                                       // Sequence number (will be replaced by the SDK)
	/* 24 - 25 */ 0x00, 0x20,                                       // Tag: Set SSID length, Tag length: 32
	/* 26 - 57 */ 0x20, 0x20,               0x20, 0x20,             // SSID
	0x20,               0x20,               0x20, 0x20,
	0x20,               0x20,               0x20, 0x20,
	0x20,               0x20,               0x20, 0x20,
	0x20,               0x20,               0x20, 0x20,
	0x20,               0x20,               0x20, 0x20,
	0x20,               0x20,               0x20, 0x20,
	0x20,               0x20,               0x20, 0x20,
	/* 58 - 59 */ 0x01, 0x08, // Tag Number: Supported Rates (1), Tag length: 8
	/* 60 */ 0x82,            // 1(B)
	/* 61 */ 0x84,            // 2(B)
	/* 62 */ 0x8b,            // 5.5(B)
	/* 63 */ 0x96,            // 11(B)
	/* 64 */ 0x24,            // 18
	/* 65 */ 0x30,            // 24
	/* 66 */ 0x48,            // 36
	/* 67 */ 0x6c             // 54
};

uint8_t probePacket2[68] = {
	/*  0 - 1  */ 0x40, 0x00,                                       // Type: Probe Request
	/*  2 - 3  */ 0x00, 0x00,                                       // Duration: 0 microseconds
	/*  4 - 9  */ 0xff, 0xff,               0xff, 0xff, 0xff, 0xff, // Destination: Broadcast
	/* 10 - 15 */ 0xAA, 0xAA,               0xAA, 0xAA, 0xAA, 0xAA, // Source: random MAC
	/* 16 - 21 */ 0xff, 0xff,               0xff, 0xff, 0xff, 0xff, // BSS Id: Broadcast
	/* 22 - 23 */ 0x00, 0x00,                                       // Sequence number (will be replaced by the SDK)
	/* 24 - 25 */ 0x00, 0x20,                                       // Tag: Set SSID length, Tag length: 32
	/* 26 - 57 */ 0x20, 0x20,               0x20, 0x20,             // SSID
	0x20,               0x20,               0x20, 0x20,
	0x20,               0x20,               0x20, 0x20,
	0x20,               0x20,               0x20, 0x20,
	0x20,               0x20,               0x20, 0x20,
	0x20,               0x20,               0x20, 0x20,
	0x20,               0x20,               0x20, 0x20,
	0x20,               0x20,               0x20, 0x20,
	/* 58 - 59 */ 0x01, 0x08, // Tag Number: Supported Rates (1), Tag length: 8
	/* 60 */ 0x82,            // 1(B)
	/* 61 */ 0x84,            // 2(B)
	/* 62 */ 0x8b,            // 5.5(B)
	/* 63 */ 0x96,            // 11(B)
	/* 64 */ 0x24,            // 18
	/* 65 */ 0x30,            // 24
	/* 66 */ 0x48,            // 36
	/* 67 */ 0x6c             // 54
};

#define BEACON_SSID_OFFSET 38
#define SRCADDR_OFFSET 10
#define BSSID_OFFSET 16
#define SEQNUM_OFFSET 22
#define TOTAL_LINES (sizeof(rick_ssids) / sizeof(char *))

esp_err_t event_handler(void *ctx, system_event_t *event) {
	return ESP_OK;
}

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type);

void send_ping (const unsigned ts) {
	probePacket[11] = 0xaa;
	*(unsigned *)(probePacket + 12) = ts;
	esp_wifi_80211_tx(WIFI_IF_AP, probePacket, sizeof(probePacket), false);
}

void send_pong (const unsigned ts) {
	probePacket2[11] = 0xab;
	*(unsigned *)(probePacket2 + 12) = ts;
	esp_wifi_80211_tx(WIFI_IF_AP, probePacket2, sizeof(probePacket2), false);
}

void spam_task(void *pvParameter) {
	for (;;) {
		vTaskDelay(1000 / portTICK_PERIOD_MS);
		unsigned const ts = xthal_get_ccount();
		send_ping(ts);
		printf("send probe @ %u\n\n", ts);
	}
}

void app_main(void) {
	nvs_flash_init();
	tcpip_adapter_init();

	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

	ESP_ERROR_CHECK(esp_event_loop_init(event_handler, NULL));
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	static wifi_country_t wifi_country = {.cc="CN", .schan=1, .nchan=13, .policy=WIFI_COUNTRY_POLICY_AUTO};
	ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */

	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

	// Init dummy AP to specify a channel and get WiFi hardware into
	// a mode where we can send the actual fake beacon frames.
	ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
	wifi_config_t ap_config = {
		.ap = {
			.ssid = "esp32-beaconspam",
			.ssid_len = 0,
			.password = "dummypassword",
			.channel = 1,
			.authmode = WIFI_AUTH_WPA2_PSK,
			.ssid_hidden = 1,
			.max_connection = 4,
			.beacon_interval = 60000
		}
	};

	ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
	ESP_ERROR_CHECK(esp_wifi_start());
	ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
	esp_wifi_set_channel(5, WIFI_SECOND_CHAN_NONE);

	esp_wifi_set_promiscuous(true);
	esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);

	//xTaskCreate(&spam_task, "spam_task", 2048, NULL, 5, NULL);
	for ( ; ; ) {
		vTaskDelay(1000 / portTICK_PERIOD_MS);
		unsigned const ts = xthal_get_ccount();
//		send_ping(ts);
//		printf("send probe @ %u\n\n", ts);
	}
}
