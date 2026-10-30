/*
  Pokemon GO Plus emulator (auto-catch only) for ESP32-C3, Arduino IDE.

  Based on pgpemu by Yohanes Nugroho (https://github.com/yohanes/pgpemu),
  BSD-style licence, (c) 2018 Yohanes Nugroho.

  Board:   Seeed Studio XIAO ESP32-C3   (arduino-esp32 core 2.0.x)
  Tools -> Partition Scheme: Huge APP (3MB No OTA/1MB SPIFFS)
  Tools -> USB CDC On Boot: Enabled  (only for the Serial log; disable for battery use)

  Serial commands (115200):  RESET = forget the paired phone,  STATUS = print state
*/

#include <Arduino.h>
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_bt.h"
#if defined(ESP_IDF_VERSION_MAJOR) && ESP_IDF_VERSION_MAJOR >= 5
  // arduino-esp32 3.x / IDF 5.x: esp_bt_main.h was merged into esp_bt.h
#else
  #include "esp_bt_main.h"
#endif
#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_gatt_common_api.h"
#include "nvs_flash.h"
#include "mbedtls/aes.h"
#include "sdkconfig.h"
#include "esp_pm.h"
#include <WiFi.h>
#include <WebServer.h>
#include <ESPmDNS.h>
#include <HTTPClient.h>
#include "esp_wifi.h"

#include "secrets.h"
#include "pgp_crypto.h"

extern "C" bool btInUse(void)  { return true; }
extern "C" bool bleInUse(void) { return true; }

#define PGP_VERBOSE 1
#define LOGF(...) do { if (PGP_VERBOSE) Serial.printf(__VA_ARGS__); } while (0)

// ============================ options =======================================
// 0 = every connection does the full certificate handshake (this is what you
//     have been running; it works). 1 = try the short "reconnect" handshake
//     after the first pairing; if it fails once, it falls back to the full one.
#define PGP_USE_RECONNECT_PATH 0

// 1 = a phone that is not the paired one is disconnected the moment it connects.
// 0 = only log what would have happened (use this to diagnose if your own phone is ever refused).
#define PGP_ENFORCE_LOCK  1

// EXPERIMENTAL. 1 = once paired, advertise a bare connectable packet with no "Pokemon GO Plus"
// name/service data, so other phones' GO apps don't list it. Your phone reconnects by address, which
// SHOULD still work, but I could not test it. If your own phone stops reconnecting, set this back to 0.
#define PGP_STEALTH_WHEN_LOCKED 0

#define BT_MAC_OFFSET     2
#define PGP_DEVICE_NAME   "Pokemon GO Plus"
#define LOCK_SCHEMA       2          // bump to force a clean pairing reset after a firmware change

#define WIFI_CHECK_MS     30000UL    // how often to look for the hotspot
#define WIFI_BACKOFF_MS   300000UL   // after WIFI_QUICK_FAILS failures in a row, only try this often
#define WIFI_QUICK_FAILS  3
#define WIFI_REG_MS       15000UL    // client -> hub registration interval
#define BT_BOND_NEEDS_RESET_MSG "(if this is YOUR phone, send RESET and pair again)"

// ============================ state =========================================
static uint8_t g_mac[6], g_key[16], g_blob[256];

static uint8_t locked_phone_mac[6];          // for display only; phones use rotating addresses
static bool    have_locked_phone = false;

static uint8_t session_key[16];              // persisted key of the last completed handshake
static bool    session_key_valid = false;
static uint8_t cert_key[16];                 // key used by the handshake currently in progress

static int     cert_state = 0;
static uint8_t reconnect_challenge[32];
static bool    reconnect_pending = false;

static bool    ble_is_connected    = false;
static bool    conn_secured        = false;  // pairing/encryption finished on this connection
static bool    conn_handshake_done = false;  // certificate handshake finished on this connection
static bool    conn_blocked        = false;  // a second (unknown) phone was detected and kicked
static uint16_t last_conn_id = 0;
static esp_gatt_if_t last_if = 0;
static uint8_t last_bda[6];
static QueueHandle_t button_queue;

static bool    wifi_focus = false;           // true while joining/using the hotspot: BLE advertising paused
static bool    adv_running = false;
static bool    adv_data_ready = false;
static unsigned long adv_last_try = 0;

// ============================ NVS ===========================================
#define NVS_NAMESPACE "pgpemu"
#define NVS_KEY_PHONE "phone_mac"
#define NVS_KEY_SESS  "session_key"
#define NVS_KEY_SCHEMA "schema"

static void load_locked_phone() {
  nvs_handle_t h;
  if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) { have_locked_phone = false; return; }
  size_t len = 6;
  esp_err_t e = nvs_get_blob(h, NVS_KEY_PHONE, locked_phone_mac, &len);
  nvs_close(h);
  have_locked_phone = (e == ESP_OK && len == 6);
}

static void save_locked_phone(const uint8_t *bda) {
  nvs_handle_t h;
  if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
    nvs_set_blob(h, NVS_KEY_PHONE, bda, 6);
    nvs_commit(h); nvs_close(h);
  }
  memcpy(locked_phone_mac, bda, 6);
  have_locked_phone = true;
  LOGF("[lock] phone locked - from now on only this phone may pair\n");
}

static void save_session_key() {
  nvs_handle_t h;
  if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) return;
  nvs_set_blob(h, NVS_KEY_SESS, session_key, 16);
  nvs_commit(h); nvs_close(h);
}

static void load_session_key() {
  nvs_handle_t h;
  session_key_valid = false;
  if (nvs_open(NVS_NAMESPACE, NVS_READONLY, &h) != ESP_OK) return;
  size_t len = 16;
  esp_err_t e = nvs_get_blob(h, NVS_KEY_SESS, session_key, &len);
  nvs_close(h);
  session_key_valid = (e == ESP_OK && len == 16);
}

// Bluedroid keeps its own bond database (in NVS too). These helpers need the BT stack running.
static void remove_other_bonds(const uint8_t *keep) {
  int n = esp_ble_get_bond_device_num();
  if (n <= 0) return;
  esp_ble_bond_dev_t *list = (esp_ble_bond_dev_t*)malloc(n * sizeof(esp_ble_bond_dev_t));
  if (!list) return;
  if (esp_ble_get_bond_device_list(&n, list) == ESP_OK) {
    for (int i = 0; i < n; i++)
      if (!keep || memcmp(list[i].bd_addr, keep, 6) != 0) esp_ble_remove_bond_device(list[i].bd_addr);
  }
  free(list);
}

// ---- who is connecting? ----------------------------------------------------
// Phones connect from rotating "private" addresses. For a phone we are bonded with, Bluedroid
// resolves that address with the phone's stored key (IRK) and reports the stable bonded address
// in the connect event. As a backup this does the same resolution itself, so a bonded phone is
// recognised either way. Spec: Core Vol 3 Part H 2.2.2 "ah": hash = AES128(IRK, 0..0||prand)[last 3 bytes].
// Bluedroid stores addresses most-significant-byte first and the IRK least-significant-byte first.
static bool rpa_resolves(const uint8_t *addr, const uint8_t *irk_le) {
  if ((addr[0] & 0xC0) != 0x40) return false;          // not a resolvable private address
  uint8_t key[16], pt[16] = {0}, out[16];
  for (int i = 0; i < 16; i++) key[i] = irk_le[15 - i];
  pt[13] = addr[0]; pt[14] = addr[1]; pt[15] = addr[2];
  pgp_aes_ecb_encrypt(key, pt, out);
  return out[13] == addr[3] && out[14] == addr[4] && out[15] == addr[5];
}

// 1 = this is a phone we are bonded with, 0 = unknown phone, -1 = no bond data to judge by
static int classify_peer(const uint8_t *bda) {
  int n = esp_ble_get_bond_device_num();
  if (n <= 0) return -1;
  esp_ble_bond_dev_t *list = (esp_ble_bond_dev_t*)malloc(n * sizeof(esp_ble_bond_dev_t));
  if (!list) return -1;
  int res = 0;
  if (esp_ble_get_bond_device_list(&n, list) == ESP_OK) {
    for (int i = 0; i < n && res == 0; i++) {
      const esp_ble_bond_dev_t &b = list[i];
      if (memcmp(b.bd_addr, bda, 6) == 0) res = 1;
      else if (b.bond_key.key_mask & ESP_LE_KEY_PID) {
        if (memcmp(b.bond_key.pid_key.static_addr, bda, 6) == 0) res = 1;
        else if (rpa_resolves(bda, b.bond_key.pid_key.irk)) res = 1;
      }
    }
  } else {
    res = -1;
  }
  free(list);
  return res;
}

static void clear_locked_phone() {
  remove_other_bonds(NULL);                  // NULL = remove every bond
  nvs_handle_t h;
  if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
    nvs_erase_key(h, NVS_KEY_PHONE);
    nvs_erase_key(h, NVS_KEY_SESS);
    nvs_commit(h); nvs_close(h);
  }
  have_locked_phone = false;
  session_key_valid = false;
  LOGF("[lock] forgotten - the next phone to pair will be remembered\n");
}

// One-time clean slate when the firmware's pairing logic changes, so stale bonds
// from older test builds can't be mistaken for a "second phone".
static void check_schema() {
  nvs_handle_t h;
  if (nvs_open(NVS_NAMESPACE, NVS_READWRITE, &h) != ESP_OK) return;
  uint8_t cur = 0;
  size_t len = 1;
  esp_err_t e = nvs_get_blob(h, NVS_KEY_SCHEMA, &cur, &len);
  if (e == ESP_OK && len == 1 && cur == LOCK_SCHEMA) { nvs_close(h); return; }
  uint8_t v = LOCK_SCHEMA;
  nvs_set_blob(h, NVS_KEY_SCHEMA, &v, 1);
  nvs_commit(h);
  nvs_close(h);
  if (have_locked_phone || session_key_valid) {
    LOGF("[lock] pairing format changed in this firmware - old pairing cleared.\n"
         "       Forget \"Pokemon GO Plus\" in your phone's Bluetooth settings, then pair again.\n");
  }
  clear_locked_phone();
}

// ============================ secrets / crypto glue =========================
static bool parse_hex(const char *s, uint8_t *out, size_t want) {
  size_t n = 0; int hi = -1;
  for (size_t i = 0; s[i]; i++) {
    char c = s[i];
    if (c == '0' && (s[i+1] == 'x' || s[i+1] == 'X') && hi < 0) { i++; continue; }
    int v;
    if      (c >= '0' && c <= '9') v = c - '0';
    else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
    else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
    else continue;
    if (hi < 0) hi = v;
    else { if (n >= want) return false; out[n++] = (hi << 4) | v; hi = -1; }
  }
  return n == want && hi < 0;
}
static bool all_zero(const uint8_t *p, size_t n) {
  for (size_t i = 0; i < n; i++) { if (p[i]) return false; }
  return true;
}

void pgp_aes_ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out) {
  mbedtls_aes_context c;
  mbedtls_aes_init(&c);
  mbedtls_aes_setkey_enc(&c, key, 128);
  mbedtls_aes_crypt_ecb(&c, MBEDTLS_AES_ENCRYPT, in, out);
  mbedtls_aes_free(&c);
}
// ============================================================================
// GATT table
// ============================================================================
enum { IDX_BATTERY_SVC,IDX_CHAR_BATTERY_LEVEL,IDX_CHAR_BATTERY_LEVEL_VAL,IDX_CHAR_BATTERY_LEVEL_CFG,BATTERY_LAST_IDX };
enum {
  IDX_LED_BUTTON_SVC,
  IDX_CHAR_LED,IDX_CHAR_LED_VAL,
  IDX_CHAR_BUTTON,IDX_CHAR_BUTTON_VAL,IDX_CHAR_BUTTON_CFG,
  IDX_CHAR_UNKNOWN,IDX_CHAR_UNKNOWN_VAL,
  IDX_CHAR_UPDATE_REQUEST,IDX_CHAR_UPDATE_REQUEST_VAL,
  IDX_CHAR_FW_VERSION,IDX_CHAR_FW_VERSION_VAL,
  LED_BUTTON_LAST_IDX
};
enum {
  IDX_CERT_SVC,
  IDX_CHAR_C2S,IDX_CHAR_C2S_VAL,
  IDX_CHAR_SFIDA_CMD,IDX_CHAR_SFIDA_CMD_VAL,IDX_CHAR_SFIDA_CMD_CFG,
  IDX_CHAR_S2C,IDX_CHAR_S2C_VAL,
  CERT_LAST_IDX
};

#define BATTERY_INST_ID    0
#define LED_BUTTON_INST_ID 1
#define CERT_INST_ID       2
#define ESP_APP_ID         0x55
#define MAX_VALUE_LEN      500
#define PREP_BUF_MAX       1024
#define DECL_SZ            (sizeof(uint8_t))

static uint16_t battery_ht[BATTERY_LAST_IDX];
static uint16_t lb_ht[LED_BUTTON_LAST_IDX];
static uint16_t cert_ht[CERT_LAST_IDX];

static const uint16_t u_svc   = ESP_GATT_UUID_PRI_SERVICE;
static const uint16_t u_decl  = ESP_GATT_UUID_CHAR_DECLARE;
static const uint16_t u_cccd  = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
static const uint8_t  p_r     = ESP_GATT_CHAR_PROP_BIT_READ;
static const uint8_t  p_w     = ESP_GATT_CHAR_PROP_BIT_WRITE;
static const uint8_t  p_rn    = ESP_GATT_CHAR_PROP_BIT_READ|ESP_GATT_CHAR_PROP_BIT_NOTIFY;
static const uint8_t  p_n     = ESP_GATT_CHAR_PROP_BIT_NOTIFY;
static const uint8_t  cc0[2]  = {0,0};
static const uint16_t U_BATT_SVC  = 0x180f;
static const uint16_t U_BATT_LVL  = 0x2a19;
static const uint8_t  batt_v[1]   = {0x60};

static uint8_t U_LB_SVC[16]  = {0xeb,0x9a,0x93,0xb9,0xb5,0x82,0x4c,0x5c,0xa3,0x63,0xcb,0x67,0x62,0x04,0xc5,0x21};
static uint8_t U_LED[16]     = {0xec,0x9a,0x93,0xb9,0xb5,0x82,0x4c,0x5c,0xa3,0x63,0xcb,0x67,0x62,0x04,0xc5,0x21};
static uint8_t U_BTN[16]     = {0xed,0x9a,0x93,0xb9,0xb5,0x82,0x4c,0x5c,0xa3,0x63,0xcb,0x67,0x62,0x04,0xc5,0x21};
static uint8_t U_UNK[16]     = {0xee,0x9a,0x93,0xb9,0xb5,0x82,0x4c,0x5c,0xa3,0x63,0xcb,0x67,0x62,0x04,0xc5,0x21};
static uint8_t U_UPD[16]     = {0xef,0x9a,0x93,0xb9,0xb5,0x82,0x4c,0x5c,0xa3,0x63,0xcb,0x67,0x62,0x04,0xc5,0x21};
static uint8_t U_FW[16]      = {0xf0,0x9a,0x93,0xb9,0xb5,0x82,0x4c,0x5c,0xa3,0x63,0xcb,0x67,0x62,0x04,0xc5,0x21};
static uint8_t U_CERT_SVC[16]= {0x37,0x8e,0x0d,0xef,0x8e,0x8b,0x7f,0xab,0x33,0x44,0x89,0x5b,0x09,0x77,0xe8,0xbb};
static uint8_t U_C2S[16]     = {0x38,0x8e,0x0d,0xef,0x8e,0x8b,0x7f,0xab,0x33,0x44,0x89,0x5b,0x09,0x77,0xe8,0xbb};
static uint8_t U_SCMD[16]    = {0x39,0x8e,0x0d,0xef,0x8e,0x8b,0x7f,0xab,0x33,0x44,0x89,0x5b,0x09,0x77,0xe8,0xbb};
static uint8_t U_S2C[16]     = {0x3a,0x8e,0x0d,0xef,0x8e,0x8b,0x7f,0xab,0x33,0x44,0x89,0x5b,0x09,0x77,0xe8,0xbb};

static uint8_t led_v[100], btn_v[2], cert_buf[378];

#define A ESP_GATT_AUTO_RSP
static const esp_gatts_attr_db_t db_batt[BATTERY_LAST_IDX]={
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_svc, ESP_GATT_PERM_READ,2,2,(uint8_t*)&U_BATT_SVC}},
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_decl,ESP_GATT_PERM_READ,1,1,(uint8_t*)&p_rn}},
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&U_BATT_LVL,ESP_GATT_PERM_READ,MAX_VALUE_LEN,1,(uint8_t*)batt_v}},
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_cccd,ESP_GATT_PERM_READ|ESP_GATT_PERM_WRITE,2,2,(uint8_t*)cc0}},
};
static const esp_gatts_attr_db_t db_lb[LED_BUTTON_LAST_IDX]={
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_svc,ESP_GATT_PERM_READ,16,16,U_LB_SVC}},
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_decl,ESP_GATT_PERM_READ,1,1,(uint8_t*)&p_w}},
  {{A},{ESP_UUID_LEN_128,U_LED,ESP_GATT_PERM_READ|ESP_GATT_PERM_WRITE,MAX_VALUE_LEN,sizeof(led_v),led_v}},
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_decl,ESP_GATT_PERM_READ,1,1,(uint8_t*)&p_n}},
  {{A},{ESP_UUID_LEN_128,U_BTN,ESP_GATT_PERM_READ,MAX_VALUE_LEN,sizeof(btn_v),btn_v}},
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_cccd,ESP_GATT_PERM_READ|ESP_GATT_PERM_WRITE,2,2,(uint8_t*)cc0}},
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_decl,ESP_GATT_PERM_READ,1,1,(uint8_t*)&p_w}},
  {{A},{ESP_UUID_LEN_128,U_UNK,ESP_GATT_PERM_READ,MAX_VALUE_LEN,sizeof(led_v),led_v}},
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_decl,ESP_GATT_PERM_READ,1,1,(uint8_t*)&p_w}},
  {{A},{ESP_UUID_LEN_128,U_UPD,ESP_GATT_PERM_READ,MAX_VALUE_LEN,sizeof(led_v),led_v}},
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_decl,ESP_GATT_PERM_READ,1,1,(uint8_t*)&p_r}},
  {{A},{ESP_UUID_LEN_128,U_FW,ESP_GATT_PERM_READ,MAX_VALUE_LEN,sizeof(led_v),led_v}},
};
static const esp_gatts_attr_db_t db_cert[CERT_LAST_IDX]={
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_svc,ESP_GATT_PERM_READ,16,16,U_CERT_SVC}},
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_decl,ESP_GATT_PERM_READ,1,1,(uint8_t*)&p_w}},
  {{A},{ESP_UUID_LEN_128,U_C2S,ESP_GATT_PERM_READ|ESP_GATT_PERM_WRITE,MAX_VALUE_LEN,sizeof(led_v),led_v}},
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_decl,ESP_GATT_PERM_READ,1,1,(uint8_t*)&p_n}},
  {{A},{ESP_UUID_LEN_128,U_SCMD,ESP_GATT_PERM_READ,MAX_VALUE_LEN,sizeof(led_v),led_v}},
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_cccd,ESP_GATT_PERM_READ|ESP_GATT_PERM_WRITE,2,2,(uint8_t*)cc0}},
  {{A},{ESP_UUID_LEN_16,(uint8_t*)&u_decl,ESP_GATT_PERM_READ,1,1,(uint8_t*)&p_r}},
  {{A},{ESP_UUID_LEN_128,U_S2C,ESP_GATT_PERM_READ,MAX_VALUE_LEN,sizeof(cert_buf),cert_buf}},
};

// ============================ advertising ===================================
// A BLE peripheral MUST advertise for any phone (including yours) to connect to
// it - there is no way to connect to a device that is not advertising. So the
// device advertises whenever it is not connected. "Only my phone" is enforced at
// pairing time instead (see the AUTH_CMPL handler): once locked, a second phone
// that tries to pair is disconnected and its bond is deleted.
static uint8_t raw_adv[] = {
  0x02,0x01,0x06,
  0x10,0x09,'P','o','k','e','m','o','n',' ','G','O',' ','P','l','u','s',
  0x06,0x20,0x62,0x04,0xC5,0x21,0x00
};
static uint8_t raw_scan_rsp[] = {0x02,0x01,0x06,0x02,0x0a,0xeb,0x03,0x03,0xFF,0x00};

#define ADV_CONFIG_FLAG      (1<<0)
#define SCAN_RSP_CONFIG_FLAG (1<<1)
static uint8_t adv_config_done = 0;

static esp_ble_adv_params_t adv_params = {
  .adv_int_min       = 0x50,   // 50 ms
  .adv_int_max       = 0xA0,   // 100 ms
  .adv_type          = ADV_TYPE_IND,
  .own_addr_type     = BLE_ADDR_TYPE_PUBLIC,
  .peer_addr         = {0},
  .peer_addr_type    = BLE_ADDR_TYPE_PUBLIC,
  .channel_map       = ADV_CHNL_ALL,
  .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

static void stop_advertising() {
  if (adv_running) {
    esp_ble_gap_stop_advertising();
    adv_running = false;
  }
}

// Optional stealth payload: still connectable (so the paired phone can reconnect by address), but
// carries nothing that says "Pokemon GO Plus". Swapped in only while idle, never mid-connection.
static uint8_t raw_adv_bare[] = {0x02,0x01,0x06};
static bool adv_payload_stealth = false;        // which payload is currently loaded

static void apply_adv_payload() {
  bool want = (PGP_STEALTH_WHEN_LOCKED != 0) && have_locked_phone;
  if (want == adv_payload_stealth) return;
  adv_payload_stealth = want;
  stop_advertising();
  adv_data_ready = false;                        // update_advertising() waits for the two events below
  adv_config_done = ADV_CONFIG_FLAG | SCAN_RSP_CONFIG_FLAG;
  if (want) {
    esp_ble_gap_config_adv_data_raw(raw_adv_bare, sizeof(raw_adv_bare));
    esp_ble_gap_config_scan_rsp_data_raw(raw_adv_bare, sizeof(raw_adv_bare));
    LOGF("[adv] stealth: no GO Plus name in the advertisement while paired\n");
  } else {
    esp_ble_gap_config_adv_data_raw(raw_adv, sizeof(raw_adv));
    esp_ble_gap_config_scan_rsp_data_raw(raw_scan_rsp, sizeof(raw_scan_rsp));
    LOGF("[adv] normal GO Plus advertisement\n");
  }
}

// Single place that decides whether we should be advertising. Called every loop.
static void update_advertising() {
  if (!adv_data_ready) return;          // never start before the advertising data is set
  if (ble_is_connected) return;         // a connection stops advertising by itself
  apply_adv_payload();                  // swaps the payload if the pairing state changed
  if (!adv_data_ready) return;          // ...and waits for the stack to confirm it
  if (wifi_focus) { stop_advertising(); return; }   // hotspot/dashboard session: BLE paused
  if (adv_running) return;
  if (millis() - adv_last_try < 1000) return;       // throttle retries
  adv_last_try = millis();
  esp_ble_gap_start_advertising(&adv_params);
  adv_running = true;                   // corrected by ADV_START_COMPLETE if it failed
}

// ============================ certificate handshake =========================
typedef struct { uint16_t handle; uint8_t *buf; int len; } prep_env_t;
static prep_env_t prep_env = {0, NULL, 0};

static void notify_cmd(esp_gatt_if_t gif, int cid, const uint8_t *d, int len) {
  esp_ble_gatts_send_indicate(gif, cid, cert_ht[IDX_CHAR_SFIDA_CMD_VAL], len, (uint8_t*)d, false);
}

static void generate_first_challenge() {
  uint8_t the_challenge[16], main_nonce[16], outer_nonce[16];
  esp_fill_random(the_challenge, 16);
  esp_fill_random(main_nonce, 16);
  esp_fill_random(cert_key, 16);          // NOT stored yet - only after the handshake completes
  esp_fill_random(outer_nonce, 16);
  pgp_generate_chal_0(g_mac, g_blob, g_key, the_challenge, main_nonce, cert_key, outer_nonce,
                      (struct challenge_data*)cert_buf);
}

// Lock to this phone once it has BOTH finished pairing/encryption AND the
// certificate handshake. The two can finish in either order depending on the phone.
static void try_lock() {
  if (have_locked_phone) return;
  if (!(conn_secured && conn_handshake_done)) return;
  // Pairing has finished, so Bluedroid now holds this phone's bond. Remember the address it keeps
  // for it (for display); the connect-time check reads the live bond list, so this is informational.
  uint8_t id[6];
  memcpy(id, last_bda, 6);
  int n = esp_ble_get_bond_device_num();
  if (n > 0) {
    esp_ble_bond_dev_t *list = (esp_ble_bond_dev_t*)malloc(n * sizeof(esp_ble_bond_dev_t));
    if (list) {
      if (esp_ble_get_bond_device_list(&n, list) == ESP_OK && n >= 1) memcpy(id, list[0].bd_addr, 6);
      free(list);
    }
  }
  if (n <= 0) LOGF("[lock] WARNING: no bond record was stored for this phone - second-phone blocking cannot work\n");
  save_locked_phone(id);
}

static void handle_protocol(esp_gatt_if_t gif, const uint8_t *buf, int len, int cid) {
  switch (cert_state) {
    case 0: {
      if (len != 20) { LOGF("[cert] step0 unexpected length %d\n", len); break; }
      uint8_t nonce[16], tmp[52];
      esp_fill_random(nonce, 16);
      memset(tmp, 0, sizeof(tmp));
      pgp_generate_next_chal(NULL, cert_key, nonce, (struct next_challenge*)tmp);
      tmp[0] = 0x01;
      memcpy(cert_buf, tmp, 52);
      esp_ble_gatts_set_attr_value(cert_ht[IDX_CHAR_S2C_VAL], 52, cert_buf);
      cert_state = 1;
      uint8_t n[4] = {0x01,0,0,0}; notify_cmd(gif, cid, n, 4);
      break;
    }
    case 1: {
      if (len < 52) { LOGF("[cert] step1 short write %d\n", len); break; }
      uint8_t tmp[20]; memset(tmp, 0, sizeof(tmp));
      pgp_decrypt_next(buf, cert_key, tmp + 4);
      tmp[0] = 0x02;
      memcpy(cert_buf, tmp, 20);
      esp_ble_gatts_set_attr_value(cert_ht[IDX_CHAR_S2C_VAL], 20, cert_buf);
      cert_state = 2;
      uint8_t n[4] = {0x02,0,0,0}; notify_cmd(gif, cid, n, 4);
      break;
    }
    case 2: {
      if (len < 52) { LOGF("[cert] step2 short write %d\n", len); break; }
      uint8_t tmp[16];
      pgp_decrypt_next(buf, cert_key, tmp);
      cert_state = 6;
      uint8_t n[4] = {0x04,0x00,0x23,0x00}; notify_cmd(gif, cid, n, 4);
      // The handshake is finished: THIS key is now the valid session key.
      memcpy(session_key, cert_key, 16);
      session_key_valid = true;
      save_session_key();
      conn_handshake_done = true;
      reconnect_pending = false;
      LOGF("[cert] handshake complete - catching enabled\n");
      try_lock();
      break;
    }
    case 3: {                                  // reconnect path (PGP_USE_RECONNECT_PATH)
      if (len != 20) break;
      uint8_t n[4] = {0x04,0x00,0x01,0x00}; notify_cmd(gif, cid, n, 4);
      cert_state = 4;
      break;
    }
    case 4: {
      if (len < 36) { LOGF("[cert] step4 short write %d\n", len); break; }
      memset(cert_buf, 0, 20);
      pgp_generate_reconnect_response(cert_key, buf + 4, cert_buf + 4);
      cert_buf[0] = 5;
      esp_ble_gatts_set_attr_value(cert_ht[IDX_CHAR_S2C_VAL], 20, cert_buf);
      uint8_t n[4] = {0x05,0,0,0}; notify_cmd(gif, cid, n, 4);
      cert_state = 5;
      break;
    }
    case 5: {
      if (len == 5) {
        uint8_t n[4] = {0x04,0x00,0x02,0x00}; notify_cmd(gif, cid, n, 4);
        cert_state = 6;
        conn_handshake_done = true;
        reconnect_pending = false;
        LOGF("[cert] reconnect complete - catching enabled\n");
        try_lock();
      }
      break;
    }
    default:
      LOGF("[cert] unhandled state %d\n", cert_state);
      break;
  }
}

// ============================ auto catch ====================================
static void handle_led_write() { int one = 1; xQueueSend(button_queue, &one, 0); }

static void auto_button_task(void *pv) {
  for (;;) {
    int e;
    if (xQueueReceive(button_queue, &e, portMAX_DELAY)) {
      if (cert_state == 6 && ble_is_connected && !conn_blocked) {
        uint8_t d[2] = {0x03, 0xff};
        esp_ble_gatts_send_indicate(last_if, last_conn_id, lb_ht[IDX_CHAR_BUTTON_VAL], sizeof(d), d, false);
        LOGF("[btn] catch\n");
      }
    }
  }
}

// Long writes (prepare + exec) are used by the Android app. The stack answers
// them automatically (ESP_GATT_AUTO_RSP) - do NOT send our own response.
static void handle_prepare_write(esp_gatt_if_t gif, esp_ble_gatts_cb_param_t *p) {
  if (!prep_env.buf) {
    prep_env.handle = p->write.handle;
    prep_env.buf = (uint8_t*)malloc(PREP_BUF_MAX);
    prep_env.len = 0;
    if (!prep_env.buf) return;
  }
  if (p->write.offset + p->write.len > PREP_BUF_MAX) return;
  memcpy(prep_env.buf + p->write.offset, p->write.value, p->write.len);
  prep_env.len += p->write.len;
}

static void handle_exec_write(esp_gatt_if_t gif, esp_ble_gatts_cb_param_t *p) {
  if (p->exec_write.exec_write_flag == ESP_GATT_PREP_WRITE_EXEC && prep_env.buf && !conn_blocked) {
    if (cert_ht[IDX_CHAR_C2S_VAL] == prep_env.handle)
      handle_protocol(gif, prep_env.buf, prep_env.len, p->exec_write.conn_id);
    else if (lb_ht[IDX_CHAR_LED_VAL] == prep_env.handle)
      handle_led_write();
  }
  if (prep_env.buf) { free(prep_env.buf); prep_env.buf = NULL; }
  prep_env.len = 0;
}

// ============================ GAP callback ==================================
static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *p) {
  switch (event) {
    case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
      adv_config_done &= ~ADV_CONFIG_FLAG;
      if (!adv_config_done) { adv_data_ready = true; update_advertising(); }
      break;
    case ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT:
      adv_config_done &= ~SCAN_RSP_CONFIG_FLAG;
      if (!adv_config_done) { adv_data_ready = true; update_advertising(); }
      break;
    case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
      if (p->adv_start_cmpl.status == ESP_BT_STATUS_SUCCESS) {
        LOGF("[adv] advertising\n");
      } else {
        adv_running = false;
        LOGF("[adv] start failed (%d) - will retry\n", (int)p->adv_start_cmpl.status);
      }
      break;
    case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
      adv_running = false;
      break;
    case ESP_GAP_BLE_SEC_REQ_EVT:
      esp_ble_gap_security_rsp(p->ble_security.ble_req.bd_addr, true);
      break;
    case ESP_GAP_BLE_AUTH_CMPL_EVT: {
      bool ok = p->ble_security.auth_cmpl.success;
      LOGF("[sec] pairing/encryption %s\n", ok ? "ok" : "failed");
      if (!ok) break;                          // fail open: never drop the owner because of a hiccup
      if (!have_locked_phone) {
        remove_other_bonds(p->ble_security.auth_cmpl.bd_addr);   // clean slate: keep only this phone
      }
      conn_secured = true;
      try_lock();
      break;
    }
    default: break;
  }
}

// ============================ GATTS callback ================================
static void gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gif, esp_ble_gatts_cb_param_t *p) {
  switch (event) {
    case ESP_GATTS_REG_EVT:
      if (p->reg.status != ESP_GATT_OK) { LOGF("[gatts] register failed\n"); return; }
      esp_ble_gap_set_device_name(PGP_DEVICE_NAME);
      esp_ble_gap_config_adv_data_raw(raw_adv, sizeof(raw_adv));            adv_config_done |= ADV_CONFIG_FLAG;
      esp_ble_gap_config_scan_rsp_data_raw(raw_scan_rsp, sizeof(raw_scan_rsp)); adv_config_done |= SCAN_RSP_CONFIG_FLAG;
      esp_ble_gatts_create_attr_tab(db_batt, gif, BATTERY_LAST_IDX,    BATTERY_INST_ID);
      esp_ble_gatts_create_attr_tab(db_lb,   gif, LED_BUTTON_LAST_IDX, LED_BUTTON_INST_ID);
      esp_ble_gatts_create_attr_tab(db_cert, gif, CERT_LAST_IDX,       CERT_INST_ID);
      break;

    case ESP_GATTS_CREAT_ATTR_TAB_EVT:
      if (p->add_attr_tab.status != ESP_GATT_OK) { LOGF("[gatts] table error 0x%x\n", p->add_attr_tab.status); break; }
      if (p->add_attr_tab.svc_uuid.len == ESP_UUID_LEN_16 && p->add_attr_tab.svc_uuid.uuid.uuid16 == U_BATT_SVC) {
        memcpy(battery_ht, p->add_attr_tab.handles, sizeof(battery_ht));
        esp_ble_gatts_start_service(battery_ht[IDX_BATTERY_SVC]);
      } else if (p->add_attr_tab.svc_uuid.len == ESP_UUID_LEN_128) {
        if (memcmp(p->add_attr_tab.svc_uuid.uuid.uuid128, U_LB_SVC, 16) == 0) {
          memcpy(lb_ht, p->add_attr_tab.handles, sizeof(lb_ht));
          esp_ble_gatts_start_service(lb_ht[IDX_LED_BUTTON_SVC]);
        } else if (memcmp(p->add_attr_tab.svc_uuid.uuid.uuid128, U_CERT_SVC, 16) == 0) {
          memcpy(cert_ht, p->add_attr_tab.handles, sizeof(cert_ht));
          esp_ble_gatts_start_service(cert_ht[IDX_CERT_SVC]);
        }
      }
      break;

    case ESP_GATTS_WRITE_EVT: {
      if (p->write.is_prep) { if (!conn_blocked) handle_prepare_write(gif, p); break; }
      if (conn_blocked) {                       // kicked phone: ignore everything it still sends
        if (p->write.need_rsp) esp_ble_gatts_send_response(gif, p->write.conn_id, p->write.trans_id, ESP_GATT_OK, NULL);
        break;
      }
      uint16_t h = p->write.handle;
      if (h == cert_ht[IDX_CHAR_SFIDA_CMD_CFG]) {
        uint16_t cfg = p->write.value[0] | (p->write.value[1] << 8);
        if (cfg == 0x0001) {
          uint8_t n[4] = {0,0,0,0};
#if PGP_USE_RECONNECT_PATH
          bool can_reconnect = have_locked_phone && session_key_valid;
#else
          bool can_reconnect = false;
#endif
          if (can_reconnect) {
            memcpy(cert_key, session_key, 16);
            esp_fill_random(reconnect_challenge, 32);
            memset(cert_buf, 0, 36); cert_buf[0] = 3; n[0] = 3;
            memcpy(cert_buf + 4, reconnect_challenge, 32);
            esp_ble_gatts_set_attr_value(cert_ht[IDX_CHAR_S2C_VAL], 36, cert_buf);
            cert_state = 3; reconnect_pending = true;
            LOGF("[cert] reconnect handshake\n");
          } else {
            generate_first_challenge();
            esp_ble_gatts_set_attr_value(cert_ht[IDX_CHAR_S2C_VAL], 378, cert_buf);
            cert_state = 0; reconnect_pending = false;
            LOGF("[cert] full handshake\n");
          }
          notify_cmd(gif, p->write.conn_id, n, 4);
        }
      } else if (h == cert_ht[IDX_CHAR_C2S_VAL]) {
        handle_protocol(gif, p->write.value, p->write.len, p->write.conn_id);
      } else if (h == lb_ht[IDX_CHAR_LED_VAL]) {
        handle_led_write();
        return;                                  // auto response, like the original
      }
      if (p->write.need_rsp) esp_ble_gatts_send_response(gif, p->write.conn_id, p->write.trans_id, ESP_GATT_OK, NULL);
      break;
    }

    case ESP_GATTS_EXEC_WRITE_EVT:
      handle_exec_write(gif, p);                 // no manual response - the stack does it
      break;

    case ESP_GATTS_CONNECT_EVT:
      LOGF("[conn] connected\n");
      memcpy(last_bda, p->connect.remote_bda, 6);
      last_conn_id = p->connect.conn_id;
      last_if = gif;
      ble_is_connected = true;
      adv_running = false;                       // the controller stops advertising on connect
      conn_secured = false; conn_handshake_done = false; conn_blocked = false;
      cert_state = 0;
      if (have_locked_phone) {
        // Decide BEFORE any pairing happens: is this the phone we are bonded with?
        int who = classify_peer(p->connect.remote_bda);
        if (who == 0) {
          LOGF("[lock] %s connection from %02X:%02X:%02X:%02X:%02X:%02X - not the paired phone. "
               BT_BOND_NEEDS_RESET_MSG "\n", PGP_ENFORCE_LOCK ? "REJECTED" : "would reject (enforcement off)",
               p->connect.remote_bda[0], p->connect.remote_bda[1], p->connect.remote_bda[2],
               p->connect.remote_bda[3], p->connect.remote_bda[4], p->connect.remote_bda[5]);
          if (PGP_ENFORCE_LOCK) {
            conn_blocked = true;
            esp_ble_gap_disconnect(p->connect.remote_bda);
            break;                               // no encryption request, no pairing, nothing
          }
        } else if (who < 0) {
          LOGF("[lock] no bond data to check this phone against - allowing it\n");
        } else {
          LOGF("[lock] recognised the paired phone\n");
        }
      }
      {
        esp_ble_conn_update_params_t cp = {};
        memcpy(cp.bda, p->connect.remote_bda, sizeof(esp_bd_addr_t));
        cp.min_int = 0x10; cp.max_int = 0x20; cp.latency = 0; cp.timeout = 400;
        esp_ble_gap_update_conn_params(&cp);
      }
      esp_ble_set_encryption(p->connect.remote_bda, ESP_BLE_SEC_ENCRYPT_MITM);
      break;

    case ESP_GATTS_DISCONNECT_EVT:
      LOGF("[conn] disconnected (0x%x)\n", p->disconnect.reason);
      if (reconnect_pending && !conn_handshake_done) {
        session_key_valid = false;               // short handshake failed: use the full one next time
        LOGF("[cert] reconnect handshake did not complete - next connection will use the full handshake\n");
      }
      reconnect_pending = false;
      cert_state = 0;
      ble_is_connected = false;
      adv_running = false;
      conn_blocked = false;
      break;                                     // update_advertising() restarts advertising from loop()

    default: break;
  }
}

// ============================ hotspot dashboard =============================
// Every WIFI_CHECK_MS the unit looks for your phone's hotspot. When it is in
// range the unit joins it, pauses BLE advertising (an already-connected phone is
// NOT dropped), and serves the dashboard. When the hotspot goes away, BLE
// advertising resumes by itself.
static WebServer adminServer(80);
static String g_device_id, g_device_label;
static char   g_host_name[24];
enum AdminState { ADMIN_IDLE, ADMIN_CONNECTED };
static AdminState admin_state = ADMIN_IDLE;
static unsigned long admin_last_action = 0;
static bool is_hub = false;
static bool routes_added = false;
static int  wifi_fail_count = 0;
static volatile int wifi_last_reason = 0;

struct DeviceInfo { String id, label, ip, status; unsigned long lastSeen; };
#define MAX_DEV 16
static DeviceInfo devs[MAX_DEV];
static int dev_count = 0;

static const char* wifi_reason_text(int r) {
  switch (r) {
    case 2:   return "authentication expired";
    case 8:   return "left the network";
    case 15:  return "4-way handshake timeout - almost always a WRONG PASSWORD (or WPA3-only hotspot)";
    case 200: return "beacon timeout (signal lost)";
    case 201: return "network not found";
    case 202: return "authentication failed - wrong password or security mode";
    case 203: return "association failed";
    case 204: return "handshake timeout - wrong password or WPA3-only hotspot";
    case 205: return "connection failed";
    default:  return "other";
  }
}

static void wifi_event_cb(arduino_event_id_t event, arduino_event_info_t info) {
  switch (event) {
    case ARDUINO_EVENT_WIFI_STA_CONNECTED:
      LOGF("[wifi] associated on channel %d\n", (int)info.wifi_sta_connected.channel);
      break;
    case ARDUINO_EVENT_WIFI_STA_GOT_IP:
      LOGF("[wifi] got IP address\n");
      break;
    case ARDUINO_EVENT_WIFI_STA_DISCONNECTED:
      wifi_last_reason = info.wifi_sta_disconnected.reason;
      LOGF("[wifi] disconnected, reason %d: %s\n", wifi_last_reason, wifi_reason_text(wifi_last_reason));
      break;
    default: break;
  }
}

static String url_enc(const String &s) {
  String o;
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') o += c;
    else { char b[4]; snprintf(b, sizeof(b), "%%%02X", (unsigned char)c); o += b; }
  }
  return o;
}

static String lock_status() {
  String s = have_locked_phone ? "Paired (locked to one phone)" : "Not paired yet";
  s += ble_is_connected ? " - phone connected" : " - waiting for phone";
  return s;
}

static void upsert_dev(const String &id, const String &label, const String &ip, const String &st) {
  for (int i = 0; i < dev_count; i++)
    if (devs[i].id == id) { devs[i].label = label; devs[i].ip = ip; devs[i].status = st; devs[i].lastSeen = millis(); return; }
  if (dev_count < MAX_DEV) {
    devs[dev_count].id = id; devs[dev_count].label = label; devs[dev_count].ip = ip;
    devs[dev_count].status = st; devs[dev_count].lastSeen = millis();
    dev_count++;
  }
}

static void purge_stale() {
  unsigned long now = millis();
  for (int i = 0; i < dev_count; ) {
    if (devs[i].id != g_device_id && now - devs[i].lastSeen > 40000UL) devs[i] = devs[--dev_count];
    else i++;
  }
}

static void do_reset_pairing() {
  clear_locked_phone();
  if (ble_is_connected) esp_ble_gap_disconnect(last_bda);
}

// ---- endpoints every unit serves ----
static void serve_ping() { adminServer.send(200, "text/plain", "OK"); }
static void serve_reset_pairing() { do_reset_pairing(); adminServer.send(200, "text/plain", "OK"); }

// ---- endpoints only the hub serves ----
static void serve_register() {
  if (!is_hub) { adminServer.send(404, "text/plain", "not hub"); return; }
  if (!adminServer.hasArg("id") || !adminServer.hasArg("status")) { adminServer.send(400, "text/plain", "BAD"); return; }
  String label = adminServer.hasArg("label") ? adminServer.arg("label") : adminServer.arg("id");
  upsert_dev(adminServer.arg("id"), label, adminServer.client().remoteIP().toString(), adminServer.arg("status"));
  adminServer.send(200, "text/plain", "OK");
}

static void serve_wipe() {
  if (!is_hub) { adminServer.send(404, "text/plain", "not hub"); return; }
  if (!adminServer.hasArg("id")) { adminServer.send(400, "text/plain", "BAD"); return; }
  String id = adminServer.arg("id");
  if (id == g_device_id) {
    do_reset_pairing();
  } else {
    for (int i = 0; i < dev_count; i++) if (devs[i].id == id) {
      HTTPClient http; http.setConnectTimeout(2000); http.setTimeout(2000);
      if (http.begin("http://" + devs[i].ip + "/reset-pairing")) { http.POST(""); http.end(); }
      break;
    }
  }
  adminServer.sendHeader("Location", "/");
  adminServer.send(303);
}

static void serve_root() {
  if (!is_hub) { adminServer.send(404, "text/plain", "not hub"); return; }
  purge_stale();
  upsert_dev(g_device_id, g_device_label, WiFi.localIP().toString(), lock_status());
  String h = "<!DOCTYPE html><html><head>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<meta http-equiv='refresh' content='5'>"
    "<style>body{font-family:sans-serif;background:#111;color:#eee;padding:16px;max-width:480px;margin:auto}"
    "h2{text-align:center}.card{background:#222;padding:12px 16px;border-radius:10px;margin:10px 0}"
    "button{background:#ff3b30;color:#fff;border:none;padding:8px 14px;border-radius:6px;margin-top:8px}"
    "</style></head><body><h2>GO Plus Units</h2>";
  for (int i = 0; i < dev_count; i++) {
    h += "<div class='card'><b>" + devs[i].label + "</b>" + (devs[i].id == g_device_id ? " (this unit)" : "");
    h += "<div>Serial: " + devs[i].id + "</div><div>IP: " + devs[i].ip + "</div>";
    h += "<div>" + devs[i].status + "</div>";
    h += "<form action='/wipe' method='POST'><input type='hidden' name='id' value='" + devs[i].id + "'>"
         "<button>Forget paired phone</button></form></div>";
  }
  h += "</body></html>";
  adminServer.send(200, "text/html", h);
}

static void admin_start_routes() {
  if (!routes_added) {               // register once; hub-only handlers check is_hub themselves
    routes_added = true;
    adminServer.on("/ping",          HTTP_GET,  serve_ping);
    adminServer.on("/reset-pairing", HTTP_POST, serve_reset_pairing);
    adminServer.on("/",              HTTP_GET,  serve_root);
    adminServer.on("/register",      HTTP_POST, serve_register);
    adminServer.on("/wipe",          HTTP_POST, serve_wipe);
  }
  adminServer.begin();
}

static void admin_on_connected() {
  esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
  delay(random(200, 1200));          // jitter so two units don't both elect themselves hub
  MDNS.end();
  MDNS.begin(g_host_name);           // a querying unit needs mDNS running to resolve ".local"
  bool found = false;
  HTTPClient http; http.setConnectTimeout(2000); http.setTimeout(2000);
  if (http.begin("http://pogo-hub.local/ping")) { found = (http.GET() == 200); http.end(); }
  is_hub = !found;
  dev_count = 0;
  if (is_hub) {
    MDNS.end();
    MDNS.begin("pogo-hub");
    MDNS.addService("http", "tcp", 80);
    upsert_dev(g_device_id, g_device_label, WiFi.localIP().toString(), lock_status());
    LOGF("[admin] DASHBOARD READY - open http://pogo-hub.local/ or http://%s/ on your phone\n",
         WiFi.localIP().toString().c_str());
  } else {
    LOGF("[admin] another unit is already the hub - this one reports to it\n");
  }
  admin_start_routes();
}

static void admin_on_disconnected() {
  adminServer.stop();
  MDNS.end();
  is_hub = false; dev_count = 0;
  WiFi.disconnect(false, false);     // drop the association but keep the WiFi driver alive
  wifi_focus = false;
  admin_last_action = millis();
  LOGF("[admin] hotspot gone - BLE advertising resumes\n");
}

static bool admin_try_connect() {
  wifi_focus = true;
  stop_advertising();

  // Clear any stale PMKSA / session state before connecting. Without this,
  // reason 2 ("authentication expired") happens on the first attempt when the
  // WiFi driver has a leftover cached credential from a previous session.
  WiFi.disconnect(false, false);
  delay(300);

  wifi_last_reason = 0;
  LOGF("[admin] joining \"%s\" ...\n", PGP_HOTSPOT_SSID);
  WiFi.begin(PGP_HOTSPOT_SSID, PGP_HOTSPOT_PASSWORD);

  unsigned long t = millis();
  while (millis() - t < 15000UL) {
    delay(250);
    wl_status_t st = WiFi.status();
    if (st == WL_CONNECTED) break;
    // Reason 2 can fire and re-trigger automatically; don't bail early on it.
  }

  if (WiFi.status() == WL_CONNECTED) {
    admin_state = ADMIN_CONNECTED;
    admin_on_connected();
    return true;
  }

  LOGF("[admin] could not join (last reason %d: %s)\n", (int)wifi_last_reason, wifi_reason_text(wifi_last_reason));
  if (wifi_last_reason == 2 || wifi_last_reason == 15 || wifi_last_reason == 204) {
    // These reasons are almost always transient (stale session, timing). Log a hint.
    LOGF("[admin] tip: if this keeps happening, set your phone hotspot to WPA2-only (not WPA3)\n");
  }
  WiFi.disconnect(false, false);
  wifi_focus = false;
  return false;
}

static void admin_loop() {
  unsigned long now = millis();
  if (WiFi.status() == WL_CONNECTED) {
    if (admin_state != ADMIN_CONNECTED) { admin_state = ADMIN_CONNECTED; wifi_focus = true; admin_on_connected(); }
    adminServer.handleClient();
    if (now - admin_last_action >= WIFI_REG_MS) {
      admin_last_action = now;
      if (is_hub) {
        upsert_dev(g_device_id, g_device_label, WiFi.localIP().toString(), lock_status());
      } else {
        HTTPClient http; http.setConnectTimeout(2000); http.setTimeout(2000);
        if (http.begin("http://pogo-hub.local/register")) {
          http.addHeader("Content-Type", "application/x-www-form-urlencoded");
          String pl = "id=" + g_device_id + "&label=" + url_enc(g_device_label) +
                      "&ip=" + WiFi.localIP().toString() + "&status=" + url_enc(lock_status());
          http.POST(pl);
          http.end();
        }
      }
    }
  } else {
    if (admin_state == ADMIN_CONNECTED) { admin_state = ADMIN_IDLE; admin_on_disconnected(); }
    unsigned long interval = (wifi_fail_count >= WIFI_QUICK_FAILS) ? WIFI_BACKOFF_MS : WIFI_CHECK_MS;
    if (now - admin_last_action >= interval) {
      admin_last_action = now;
      int n = WiFi.scanNetworks(false, false, false, 300, 0, PGP_HOTSPOT_SSID);
      bool found = false;
      for (int i = 0; i < n; i++) {
        if (WiFi.SSID(i) == PGP_HOTSPOT_SSID) {
          found = true;
          LOGF("[admin] hotspot in range: channel %d, signal %d dBm, security type %d\n",
               (int)WiFi.channel(i), (int)WiFi.RSSI(i), (int)WiFi.encryptionType(i));
          break;
        }
      }
      WiFi.scanDelete();
      if (found) { if (admin_try_connect()) wifi_fail_count = 0; else wifi_fail_count++; }
      else wifi_fail_count = 0;
    }
  }
}

// ============================ setup / loop ==================================
static void halt(const char *msg) { for (;;) { Serial.println(msg); delay(2000); } }

void setup() {
  setCpuFrequencyMhz(80);
  Serial.begin(115200);
  delay(1500);
  Serial.println("\nGO Plus emulator - auto-catch - ESP32-C3");

  if (!parse_hex(PGP_MAC_HEX, g_mac, 6))           halt("secrets.h: PGP_MAC_HEX must be 6 bytes");
  if (!parse_hex(PGP_DEVICE_KEY_HEX, g_key, 16))   halt("secrets.h: PGP_DEVICE_KEY_HEX must be 16 bytes");
  if (!parse_hex(PGP_BLOB_HEX, g_blob, 256))       halt("secrets.h: PGP_BLOB_HEX must be 256 bytes");
  if (all_zero(g_mac, 6) || all_zero(g_key, 16) || all_zero(g_blob, 256)) halt("secrets.h still has placeholder zeros");
  if (g_mac[0] & 0x01) halt("secrets.h: MAC first byte is odd");

  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) { nvs_flash_erase(); nvs_flash_init(); }

  uint64_t m = 0; for (int i = 0; i < 6; i++) m = (m << 8) | g_mac[i];
  m -= BT_MAC_OFFSET;
  uint8_t base[6]; for (int i = 5; i >= 0; i--) { base[i] = m & 0xff; m >>= 8; }
  if (esp_base_mac_addr_set(base) != ESP_OK) halt("esp_base_mac_addr_set failed");

  load_locked_phone();
  load_session_key();

  button_queue = xQueueCreate(10, sizeof(int));
  xTaskCreate(auto_button_task, "btn", 3072, NULL, 5, NULL);

  esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
  if (esp_bt_controller_init(&bt_cfg) != ESP_OK)              halt("bt controller init failed");
  if (esp_bt_controller_enable(ESP_BT_MODE_BLE) != ESP_OK)    halt("bt controller enable failed");
  if (esp_bluedroid_init() != ESP_OK)                         halt("bluedroid init failed");
  if (esp_bluedroid_enable() != ESP_OK)                       halt("bluedroid enable failed");
  Serial.printf("[power] BT modem sleep: %s\n", esp_bt_sleep_enable() == ESP_OK ? "enabled" : "not available");

  esp_ble_gatts_register_callback(gatts_event_handler);
  esp_ble_gap_register_callback(gap_event_handler);
  esp_ble_gatts_app_register(ESP_APP_ID);

  esp_ble_auth_req_t auth = ESP_LE_AUTH_BOND;
  esp_ble_io_cap_t   ioc  = ESP_IO_CAP_NONE;
  uint8_t ksz = 16, ik = ESP_BLE_ENC_KEY_MASK | ESP_BLE_ID_KEY_MASK, rk = ik;
  esp_ble_gap_set_security_param(ESP_BLE_SM_AUTHEN_REQ_MODE, &auth, 1);
  esp_ble_gap_set_security_param(ESP_BLE_SM_IOCAP_MODE,      &ioc,  1);
  esp_ble_gap_set_security_param(ESP_BLE_SM_MAX_KEY_SIZE,    &ksz,  1);
  esp_ble_gap_set_security_param(ESP_BLE_SM_SET_INIT_KEY,    &ik,   1);
  esp_ble_gap_set_security_param(ESP_BLE_SM_SET_RSP_KEY,     &rk,   1);
  esp_ble_gatt_set_local_mtu(500);

  check_schema();                    // needs the BT stack running (it may delete old bonds)
  Serial.printf("[lock] %s\n", have_locked_phone
    ? "paired - only that phone may pair (send RESET to forget it)"
    : "not paired yet - the first phone to finish pairing is locked in");

  uint8_t bt[6]; esp_read_mac(bt, ESP_MAC_BT);
  Serial.printf("BT MAC: %02X:%02X:%02X:%02X:%02X:%02X -> %s\n", bt[0], bt[1], bt[2], bt[3], bt[4], bt[5],
                memcmp(bt, g_mac, 6) == 0 ? "matches dump" : "MISMATCH (adjust BT_MAC_OFFSET)");

  // WiFi last, once the BLE stack has settled (they share one radio).
  delay(500);
  uint64_t chipid = ESP.getEfuseMac();
  char idbuf[13]; snprintf(idbuf, sizeof(idbuf), "%04X%08X", (uint16_t)(chipid >> 32), (uint32_t)chipid);
  g_device_id = String(idbuf);
  g_device_label = (strlen(PGP_DEVICE_LABEL) > 0) ? String(PGP_DEVICE_LABEL) : g_device_id;
  snprintf(g_host_name, sizeof(g_host_name), "pogo-%04X", (uint16_t)chipid);
  WiFi.onEvent(wifi_event_cb);
  WiFi.persistent(false);
  WiFi.setAutoReconnect(false);
  WiFi.mode(WIFI_STA);
  delay(300);
  Serial.printf("[admin] serial %s - looking for hotspot \"%s\" every %lus\n",
                g_device_id.c_str(), PGP_HOTSPOT_SSID, WIFI_CHECK_MS / 1000UL);

#ifdef CONFIG_PM_ENABLE
  esp_pm_config_t pm = { .max_freq_mhz = 80, .min_freq_mhz = 80, .light_sleep_enable = true };
  Serial.printf("[power] light sleep: %s\n", esp_pm_configure(&pm) == ESP_OK ? "enabled" : "failed");
#else
  Serial.println("[power] light sleep: not in this core build (battery life ~1.5-2.5 days)");
#endif
}

void loop() {
  static String ln;
  while (Serial.available()) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      ln.trim();
      if (ln.equalsIgnoreCase("RESET")) {
        do_reset_pairing();
        Serial.println("[lock] reset done - forget \"Pokemon GO Plus\" on the phone too, then pair again");
      } else if (ln.equalsIgnoreCase("STATUS")) {
        Serial.printf("[status] ble=%s paired=%s session_key=%s cert_state=%d bonds=%d advertising=%s wifi=%s\n",
          ble_is_connected ? "connected" : "idle", have_locked_phone ? "yes" : "no",
          session_key_valid ? "yes" : "no", cert_state, esp_ble_get_bond_device_num(),
          adv_running ? "yes" : "no", admin_state == ADMIN_CONNECTED ? "dashboard" : "off");
      }
      ln = "";
    } else if (ln.length() < 32) ln += c;
  }
  admin_loop();
  update_advertising();
  delay(20);
}
