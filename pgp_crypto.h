// Crypto helpers for the GO Plus certificate handshake.
// Ported from pgpemu (c) 2018 Yohanes Nugroho, BSD-style licence.
#pragma once
#include <stdint.h>
#include <string.h>

// Provide: void pgp_aes_ecb_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);
// (on the ESP32 this is implemented with mbedtls, on a PC test with tiny-AES)
void pgp_aes_ecb_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out);

struct main_challenge_data {
  uint8_t bt_addr[6];
  uint8_t key[16];
  uint8_t nonce[16];
  uint8_t encrypted_challenge[16];
  uint8_t encrypted_hash[16];
  uint8_t flash_data[10];
} __attribute__((packed));

struct challenge_data {
  uint8_t state[4];
  uint8_t nonce[16];
  uint8_t encrypted_main_challenge[80];
  uint8_t encrypted_hash[16];
  uint8_t bt_addr[6];
  uint8_t blob[256];
} __attribute__((packed));

struct next_challenge {
  uint8_t state[4];
  uint8_t nonce[16];
  uint8_t encrypted_challenge[16];
  uint8_t encrypted_hash[16];
} __attribute__((packed));

static inline void pgp_nonce_hash_init(const uint8_t *n, int len, uint8_t *o) {
  memcpy(o + 1, n, 13);
  o[0] = 57;
  o[14] = (len >> 8) & 0xff;
  o[15] = len & 0xff;
}

static inline void pgp_nonce_ctr_init(const uint8_t *n, uint8_t *o) {
  memcpy(o + 1, n, 13);
  o[0] = 1;
  o[14] = 0;
  o[15] = 0;
}

static inline void pgp_aes_hash(const uint8_t *key, const uint8_t *nonce,
                                const uint8_t *data, int count, uint8_t *out) {
  uint8_t tmp[16], tmp2[16], nh[16];
  pgp_nonce_hash_init(nonce, count, nh);
  pgp_aes_ecb_encrypt(key, nh, tmp);
  for (int b = 0; b < count / 16; b++) {
    for (int j = 0; j < 16; j++) tmp[j] ^= data[b * 16 + j];
    memcpy(tmp2, tmp, 16);
    pgp_aes_ecb_encrypt(key, tmp2, tmp);
  }
  memcpy(out, tmp, 16);
}

static inline void pgp_encrypt_block(const uint8_t *key, const uint8_t *iv,
                                     const uint8_t *nonce, uint8_t *out) {
  uint8_t ctr[16], tmp[16];
  pgp_nonce_ctr_init(nonce, ctr);
  pgp_aes_ecb_encrypt(key, ctr, tmp);
  for (int i = 0; i < 16; i++) out[i] = tmp[i] ^ iv[i];
}

static inline void pgp_aes_ctr(const uint8_t *key, const uint8_t *nonce,
                               const uint8_t *data, int count, uint8_t *out) {
  uint8_t ctr[16], e[16];
  pgp_nonce_ctr_init(nonce, ctr);
  for (int b = 0; b < count / 16; b++) {
    ctr[15]++;
    if (ctr[15] == 0) ctr[14]++;
    pgp_aes_ecb_encrypt(key, ctr, e);
    for (int j = 0; j < 16; j++) out[b * 16 + j] = e[j] ^ data[b * 16 + j];
  }
}

// mac: the dumped MAC in normal (display) order. blob: 256 bytes. device_key: 16 bytes.
static inline void pgp_generate_chal_0(const uint8_t *mac, const uint8_t *blob,
                                       const uint8_t *device_key,
                                       const uint8_t *the_challenge,
                                       const uint8_t *main_nonce,
                                       const uint8_t *main_key,
                                       const uint8_t *outer_nonce,
                                       struct challenge_data *out) {
  uint8_t revmac[6], h[16];
  struct main_challenge_data m;
  for (int i = 0; i < 6; i++) revmac[i] = mac[5 - i];
  memcpy(m.bt_addr, revmac, 6);
  memcpy(m.key, main_key, 16);
  memcpy(m.nonce, main_nonce, 16);
  memset(m.flash_data, 0, 10);

  pgp_aes_ctr(main_key, m.nonce, the_challenge, 16, m.encrypted_challenge);
  pgp_aes_hash(main_key, m.nonce, the_challenge, 16, h);
  pgp_encrypt_block(main_key, h, m.nonce, m.encrypted_hash);

  memset(out->state, 0, 4);
  memcpy(out->nonce, outer_nonce, 16);
  memcpy(out->bt_addr, revmac, 6);
  memcpy(out->blob, blob, 256);
  pgp_aes_hash(device_key, out->nonce, (uint8_t *)&m, 80, h);
  pgp_encrypt_block(device_key, h, out->nonce, out->encrypted_hash);
  pgp_aes_ctr(device_key, out->nonce, (uint8_t *)&m, 80, out->encrypted_main_challenge);
}

static inline void pgp_generate_next_chal(const uint8_t *in, const uint8_t *key,
                                          const uint8_t *nonce, struct next_challenge *out) {
  uint8_t data[16], h[16];
  if (in) memcpy(data, in, 16);
  else { memset(data, 0, 16); data[0] = 0xaa; }
  memcpy(out->nonce, nonce, 16);
  pgp_aes_ctr(key, out->nonce, data, 16, out->encrypted_challenge);
  pgp_aes_hash(key, out->nonce, data, 16, h);
  pgp_encrypt_block(key, h, out->nonce, out->encrypted_hash);
}

static inline int pgp_decrypt_next(const uint8_t *data, const uint8_t *key, uint8_t *out) {
  const struct next_challenge *c = (const struct next_challenge *)data;
  uint8_t enc_nonce[16], h[16];
  pgp_aes_ctr(key, c->nonce, c->encrypted_challenge, 16, out);
  pgp_encrypt_block(key, c->encrypted_hash, c->nonce, enc_nonce);
  pgp_aes_hash(key, c->nonce, out, 16, h);
  return memcmp(h, enc_nonce, 16) == 0;
}

static inline void pgp_generate_reconnect_response(const uint8_t *key, const uint8_t *challenge, uint8_t *out) {
  pgp_aes_ecb_encrypt(key, challenge, out);
  for (int i = 0; i < 16; i++) out[i] ^= challenge[i + 16];
}
