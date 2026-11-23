#include "HamTxPolicy.h"
#include <Utils.h>
#include <MeshCore.h>
#include <string.h>
#include <ctype.h>

#define HAM_PREFS_FILE     "/ham_prefs"
#define HAM_PREFS_MAGIC    0x48   // 'H'
#define HAM_PREFS_VERSION  1

// The well-known MeshCore "Public" channel key: base64 izOH6cXN6mrJ5e26oRXNcg==
static const uint8_t PUBLIC_CHANNEL_KEY[16] = {
  0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a, 0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72
};

static bool containsNoCase(const char* haystack, const char* needle) {
  size_t n = strlen(needle);
  if (n == 0) return false;
  for (const char* h = haystack; *h; h++) {
    size_t i = 0;
    while (i < n && h[i] && tolower((unsigned char)h[i]) == tolower((unsigned char)needle[i])) i++;
    if (i == n) return true;
  }
  return false;
}

static File openWrite(FILESYSTEM* fs, const char* filename) {
#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  fs->remove(filename);
  return fs->open(filename, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
  return fs->open(filename, "w");
#else
  return fs->open(filename, "w", true);
#endif
}

HamTxPolicy::HamTxPolicy() {
  memset(&_prefs, 0, sizeof(_prefs));
  _prefs.enabled = 0;
  _prefs.pub_dbm = HAM_PUB_TX_POWER;
  _prefs.enc_dbm = HAM_ENC_TX_POWER;
#ifdef HAM_CALLSIGN
  strncpy(_prefs.callsign, HAM_CALLSIGN, sizeof(_prefs.callsign) - 1);
#endif
#ifdef HAM_ENABLED
  _prefs.enabled = HAM_ENABLED;
#endif
  _self_pub_key = NULL;
  _n_pub = _n_enc = 0;
  rebuildKeys();
}

void HamTxPolicy::deriveHashtagKey(const char* name, uint8_t secret16[16]) {
  // MeshCore hashtag channel key = first 16 bytes of sha256("#name")
  mesh::Utils::sha256(secret16, 16, (const uint8_t*)name, strlen(name));
}

void HamTxPolicy::rebuildKeys() {
  memset(&_public, 0, sizeof(_public));
  memcpy(_public.secret, PUBLIC_CHANNEL_KEY, 16);
  mesh::Utils::sha256(&_public.hash, 1, _public.secret, 16);

  for (int i = 0; i < HAM_MAX_TAGS; i++) {
    memset(&_tag_keys[i], 0, sizeof(_tag_keys[i]));
    if (_prefs.tags[i][0]) {
      deriveHashtagKey(_prefs.tags[i], _tag_keys[i].secret);
      mesh::Utils::sha256(&_tag_keys[i].hash, 1, _tag_keys[i].secret, 16);
    }
  }
}

void HamTxPolicy::load(FILESYSTEM* fs) {
  if (!fs->exists(HAM_PREFS_FILE)) return;   // keep defaults
#if defined(RP2040_PLATFORM)
  File file = fs->open(HAM_PREFS_FILE, "r");
#else
  File file = fs->open(HAM_PREFS_FILE);
#endif
  if (!file) return;

  uint8_t hdr[2];
  HamTxPrefs tmp;
  bool ok = file.read(hdr, 2) == 2 && hdr[0] == HAM_PREFS_MAGIC && hdr[1] == HAM_PREFS_VERSION;
  ok = ok && file.read((uint8_t*)&tmp, sizeof(tmp)) == sizeof(tmp);
  file.close();

  if (ok) {
    tmp.callsign[sizeof(tmp.callsign) - 1] = 0;
    for (int i = 0; i < HAM_MAX_TAGS; i++) tmp.tags[i][HAM_TAG_MAX_LEN - 1] = 0;
    tmp.pub_dbm = constrain(tmp.pub_dbm, -9, 30);
    tmp.enc_dbm = constrain(tmp.enc_dbm, -9, 30);
    _prefs = tmp;
    rebuildKeys();
  }
}

bool HamTxPolicy::save(FILESYSTEM* fs) {
  File file = openWrite(fs, HAM_PREFS_FILE);
  if (!file) return false;
  uint8_t hdr[2] = { HAM_PREFS_MAGIC, HAM_PREFS_VERSION };
  bool ok = file.write(hdr, 2) == 2;
  ok = ok && file.write((const uint8_t*)&_prefs, sizeof(_prefs)) == sizeof(_prefs);
  file.close();
  return ok;
}

bool HamTxPolicy::matchesKnownKey(const uint8_t* payload, int len) const {
  // GRP_TXT / GRP_DATA payload: channel_hash(1) | MAC(2) | ciphertext
  if (len < 1 + CIPHER_MAC_SIZE + CIPHER_BLOCK_SIZE) return false;
  uint8_t hash = payload[0];
  const uint8_t* mac_and_data = &payload[1];
  int mac_len = len - 1;
  uint8_t scratch[MAX_PACKET_PAYLOAD];

  // Hash alone is only 1 byte (collides with private channels 1 in 256), so we require the MAC to verify.
  if (hash == _public.hash && mesh::Utils::MACThenDecrypt(_public.secret, scratch, mac_and_data, mac_len) > 0) {
    return true;
  }
  for (int i = 0; i < HAM_MAX_TAGS; i++) {
    if (_prefs.tags[i][0] && hash == _tag_keys[i].hash
        && mesh::Utils::MACThenDecrypt(_tag_keys[i].secret, scratch, mac_and_data, mac_len) > 0) {
      return true;
    }
  }
  return false;
}

HamTxClass HamTxPolicy::classify(const mesh::Packet* pkt) const {
  switch (pkt->getPayloadType()) {
    case PAYLOAD_TYPE_ADVERT:     // signed, not encrypted
    case PAYLOAD_TYPE_ACK:        // 4-byte checksum, carries no message content
    case PAYLOAD_TYPE_TRACE:      // plaintext tag + SNR list
    case PAYLOAD_TYPE_CONTROL:    // plaintext discovery
      return HAM_TX_PUBLIC;

    case PAYLOAD_TYPE_MULTIPART:  // only multipart ACKs are public
      return (pkt->payload_len >= 1 && (pkt->payload[0] & 0x0F) == PAYLOAD_TYPE_ACK) ? HAM_TX_PUBLIC : HAM_TX_ENCRYPTED;

    case PAYLOAD_TYPE_GRP_TXT:
    case PAYLOAD_TYPE_GRP_DATA:
      return matchesKnownKey(pkt->payload, pkt->payload_len) ? HAM_TX_PUBLIC : HAM_TX_ENCRYPTED;

    default:                      // REQ, RESPONSE, TXT_MSG, ANON_REQ, PATH, RAW_CUSTOM, unknown
      return HAM_TX_ENCRYPTED;
  }
}

const char* HamTxPolicy::inactiveReason(const char* node_name) const {
  if (!_prefs.enabled) return "disabled";
  if (_prefs.callsign[0] == 0) return "no callsign";
  if (!containsNoCase(node_name, _prefs.callsign)) return "name lacks callsign";
  return NULL;
}

bool HamTxPolicy::isActive(const char* node_name) const {
  return inactiveReason(node_name) == NULL;
}

int8_t HamTxPolicy::selectPower(const mesh::Packet* pkt, const char* node_name, int8_t default_dbm) {
  if (!isActive(node_name)) return default_dbm;
  if (classify(pkt) == HAM_TX_ENCRYPTED) {
    _n_enc++;
    return _prefs.enc_dbm;
  }
  _n_pub++;
  return _prefs.pub_dbm;
}

int HamTxPolicy::findTag(const char* name) const {
  for (int i = 0; i < HAM_MAX_TAGS; i++) {
    if (_prefs.tags[i][0] && strcmp(_prefs.tags[i], name) == 0) return i;
  }
  return -1;
}

// If 'p' starts with word 'w' (followed by a space or end of string), skip it plus spaces and return true.
static bool takeWord(const char*& p, const char* w) {
  size_t n = strlen(w);
  if (strncmp(p, w, n) != 0 || (p[n] != 0 && p[n] != ' ')) return false;
  p += n;
  while (*p == ' ') p++;
  return true;
}

static bool parseDbm(const char* s, int8_t& out) {
  if (*s == 0) return false;
  if (*s == '-' || *s == '+') { if (s[1] < '0' || s[1] > '9') return false; }
  else if (*s < '0' || *s > '9') return false;
  int v = atoi(s);
  if (v < -9 || v > 30) return false;
  out = (int8_t)v;
  return true;
}

// shared by 'ham public' and 'ham private'
static void handlePower(const char* p, int8_t& value, const char* what, char* reply, bool& dirty) {
  if (*p == 0) {
    sprintf(reply, "%s power is %d", what, value);
  } else if (parseDbm(p, value)) {
    dirty = true;
    sprintf(reply, "OK - %s power set to %d", what, value);
  } else {
    strcpy(reply, "Error: power must be a number from -9 to 30");
  }
}

void HamTxPolicy::listChannels(char* reply) const {
  char* dp = reply;
  dp += sprintf(dp, "Public power channels: Public");
  for (int i = 0; i < HAM_MAX_TAGS; i++) {
    if (_prefs.tags[i][0]) {
      if ((dp - reply) + strlen(_prefs.tags[i]) + 6 > 150) { strcpy(dp, ", ..."); break; }
      dp += sprintf(dp, ", %s", _prefs.tags[i]);
    }
  }
}

bool HamTxPolicy::handleCommand(const char* command, char* reply, const char* node_name, bool& dirty) {
  dirty = false;
  const char* p = command;
  if (!takeWord(p, "ham")) return false;

  // NOTE: CLI reply buffers are ~160 chars, keep every reply shorter than that.

  if (*p == 0 || takeWord(p, "status")) {
    const char* why = inactiveReason(node_name);
    int n = 0;
    for (int i = 0; i < HAM_MAX_TAGS; i++) if (_prefs.tags[i][0]) n++;
    if (why == NULL) {
      sprintf(reply, "ON - callsign %s, public power %d, private power %d, extra channels %d",
        _prefs.callsign, _prefs.pub_dbm, _prefs.enc_dbm, n);
    } else if (!_prefs.enabled) {
      sprintf(reply, "OFF - all packets use normal 'tx' power. Type: ham on");
    } else if (_prefs.callsign[0] == 0) {
      strcpy(reply, "WAITING - no callsign set. Type: ham callsign YOURCALL");
    } else {
      sprintf(reply, "WAITING - node name must include %s. Type: set name %s ...", _prefs.callsign, _prefs.callsign);
    }

  } else if (takeWord(p, "help")) {
    strcpy(reply, "ham on|off, ham callsign X, ham public N, ham private N, "
                  "ham channel add #x, ham channel remove #x, ham channels, ham stats");

  } else if (takeWord(p, "on")) {
    _prefs.enabled = 1; dirty = true;
    const char* why = inactiveReason(node_name);
    if (why == NULL) strcpy(reply, "OK - ham mode ON");
    else if (_prefs.callsign[0] == 0) strcpy(reply, "OK - but still WAITING: set callsign with 'ham callsign YOURCALL'");
    else sprintf(reply, "OK - but still WAITING: node name must include %s", _prefs.callsign);

  } else if (takeWord(p, "off")) {
    _prefs.enabled = 0; dirty = true;
    strcpy(reply, "OK - ham mode OFF, all packets use normal 'tx' power");

  } else if (takeWord(p, "callsign") || takeWord(p, "call")) {
    if (*p == 0) {
      if (_prefs.callsign[0]) sprintf(reply, "callsign is %s", _prefs.callsign);
      else strcpy(reply, "no callsign set");
    } else {
      char tmp[HAM_CALLSIGN_MAX_LEN];
      int i = 0;
      while (p[i] && p[i] != ' ' && i < HAM_CALLSIGN_MAX_LEN - 1) { tmp[i] = toupper((unsigned char)p[i]); i++; }
      tmp[i] = 0;
      if (p[i] != 0) {
        strcpy(reply, "Error: callsign must be one word, max 10 characters");
      } else {
        strcpy(_prefs.callsign, tmp);
        dirty = true;
        if (containsNoCase(node_name, _prefs.callsign)) sprintf(reply, "OK - callsign set to %s", _prefs.callsign);
        else sprintf(reply, "OK - callsign %s. Now put it in the node name: set name %s ...", _prefs.callsign, _prefs.callsign);
      }
    }

  } else if (takeWord(p, "public") || takeWord(p, "pub")) {
    handlePower(p, _prefs.pub_dbm, "public", reply, dirty);

  } else if (takeWord(p, "private") || takeWord(p, "enc")) {
    handlePower(p, _prefs.enc_dbm, "private", reply, dirty);

  } else if (takeWord(p, "channels") || takeWord(p, "tags")) {
    listChannels(reply);

  } else if (takeWord(p, "channel") || takeWord(p, "tag")) {
    if (*p == 0 || takeWord(p, "list")) {
      listChannels(reply);
      return true;
    }
    bool add = takeWord(p, "add");
    bool remove = !add && (takeWord(p, "remove") || takeWord(p, "del") || takeWord(p, "delete"));
    if (!add && !remove) {
      strcpy(reply, "Error: use 'ham channel add #name' or 'ham channel remove #name'");
      return true;
    }
    char tag[HAM_TAG_MAX_LEN];
    int len = 0;
    if (*p != '#') tag[len++] = '#';
    while (*p && *p != ' ' && len < HAM_TAG_MAX_LEN - 1) tag[len++] = *p++;
    tag[len] = 0;
    if (len < 2 || *p) {
      sprintf(reply, "Error: channel name must be one word, max %d characters", HAM_TAG_MAX_LEN - 2);
    } else if (add) {
      if (findTag(tag) >= 0) {
        sprintf(reply, "%s is already on the list", tag);
      } else {
        int slot = -1;
        for (int i = 0; i < HAM_MAX_TAGS && slot < 0; i++) if (_prefs.tags[i][0] == 0) slot = i;
        if (slot < 0) {
          sprintf(reply, "Error: list is full (max %d). Remove one first", HAM_MAX_TAGS);
        } else {
          strcpy(_prefs.tags[slot], tag);
          rebuildKeys();
          dirty = true;
          sprintf(reply, "OK - %s now uses public power", tag);
        }
      }
    } else {
      int i = findTag(tag);
      if (i < 0) {
        sprintf(reply, "%s is not on the list", tag);
      } else {
        _prefs.tags[i][0] = 0;
        rebuildKeys();
        dirty = true;
        sprintf(reply, "OK - %s removed, now uses private power", tag);
      }
    }

  } else if (takeWord(p, "stats")) {
    sprintf(reply, "Sent since boot: %lu public, %lu private", (unsigned long)_n_pub, (unsigned long)_n_enc);

  } else {
    strcpy(reply, "Unknown ham command. Type: ham help");
  }
  return true;
}
