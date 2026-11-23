#pragma once

/*
 * HamTxPolicy -- per-packet TX power selection for dual-use (Part 15 / Part 97) MeshCore nodes.
 *
 * Every outbound packet is classified as either:
 *
 *   HAM_TX_PUBLIC     content anyone can read: adverts (signed plaintext), ACKs, traces,
 *                     discovery/control, and group messages whose MAC verifies against a
 *                     *publicly known* key (the default Public channel, or a #hashtag
 *                     channel listed with 'ham channel add').
 *
 *   HAM_TX_ENCRYPTED  everything else: direct messages, logins/requests/responses, returned
 *                     paths, anon requests, raw/custom data, and group messages on private
 *                     (random-key) channels or unlisted hashtag channels.
 *
 * PUBLIC packets are sent at 'pub_dbm' (amateur power), ENCRYPTED packets at 'enc_dbm'.
 * The classification is applied to everything the node transmits, including packets it is
 * only forwarding, which is what matters for a repeater.
 *
 * Fail-safe rules:
 *   - Ham mode is only ACTIVE when enabled AND a callsign is set AND the node name contains
 *     that callsign (so adverts carry the ID). If not active, every packet uses the normal
 *     'set tx' power.
 *   - Anything that can't be positively identified as public is ENCRYPTED.
 *
 * Adverts are left completely alone: this firmware sends no extra adverts. Station ID is
 * up to the operator (normal scheduled/manual adverts carry the node name and callsign).
 */

#include <Arduino.h>   // needed for PlatformIO
#include <Packet.h>
#include <helpers/IdentityStore.h>   // FILESYSTEM

#ifndef HAM_MAX_TAGS
  #define HAM_MAX_TAGS          8
#endif
#define HAM_TAG_MAX_LEN        24    // incl. leading '#' and null terminator
#define HAM_CALLSIGN_MAX_LEN   11

#ifndef HAM_PUB_TX_POWER
  #ifdef LORA_TX_POWER
    #define HAM_PUB_TX_POWER   LORA_TX_POWER
  #else
    #define HAM_PUB_TX_POWER   20
  #endif
#endif
#ifndef HAM_ENC_TX_POWER
  #define HAM_ENC_TX_POWER     10
#endif
enum HamTxClass : uint8_t {
  HAM_TX_PUBLIC    = 0,
  HAM_TX_ENCRYPTED = 1,
};

struct HamTxPrefs {
  uint8_t  enabled;
  int8_t   pub_dbm;
  int8_t   enc_dbm;
  uint8_t  unused1;          // layout kept so existing /ham_prefs files still load
  uint16_t unused2;
  uint16_t unused3;
  char     callsign[HAM_CALLSIGN_MAX_LEN];
  char     tags[HAM_MAX_TAGS][HAM_TAG_MAX_LEN];
};

class HamTxPolicy {
  HamTxPrefs _prefs;
  const uint8_t* _self_pub_key;

  struct KnownKey {
    uint8_t secret[32];   // 16-byte AES key, zero padded (as used by Mesh for HMAC)
    uint8_t hash;
  };
  KnownKey _public;
  KnownKey _tag_keys[HAM_MAX_TAGS];

  // stats
  uint32_t _n_pub, _n_enc;

  void rebuildKeys();
  bool matchesKnownKey(const uint8_t* payload, int len) const;
  int  findTag(const char* name) const;
  void listChannels(char* reply) const;

public:
  HamTxPolicy();

  void begin(const uint8_t* self_pub_key) { _self_pub_key = self_pub_key; rebuildKeys(); }
  void load(FILESYSTEM* fs);
  bool save(FILESYSTEM* fs);

  static void deriveHashtagKey(const char* name, uint8_t secret16[16]);

  /** classify a packet that is about to be transmitted */
  HamTxClass classify(const mesh::Packet* pkt) const;

  /** true if per-packet power switching is in effect (enabled + callsign in node name) */
  bool isActive(const char* node_name) const;
  /** short reason why ham mode isn't active, or NULL if it is */
  const char* inactiveReason(const char* node_name) const;

  /**
   * Called just before a packet goes on air. Returns the TX power (dBm) to use.
   * When not active, returns 'default_dbm'.
   */
  int8_t selectPower(const mesh::Packet* pkt, const char* node_name, int8_t default_dbm);

  /**
   * Handles 'ham ...' CLI commands. Returns true if the command was a ham command (reply filled in).
   * Sets 'dirty' when prefs changed and should be saved.
   */
  bool handleCommand(const char* command, char* reply, const char* node_name, bool& dirty);

  const HamTxPrefs& prefs() const { return _prefs; }
};
