#include "HamTxPolicy.h"
#include <Utils.h>
#include <MeshCore.h>
#include <string.h>
#include <ctype.h>

#define HAM_PREFS_FILE     "/ham_prefs"
#define HAM_PREFS_BACKUP   "/ham_prefs.bak"
#define HAM_PREFS_MAGIC    0x48   // 'H'
#define HAM_PREFS_VERSION  2      // v2 = v1 record + CRC-16 trailer

// The well-known MeshCore "Public" channel key: base64 izOH6cXN6mrJ5e26oRXNcg==
static const uint8_t PUBLIC_CHANNEL_KEY[16] = {
  0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a, 0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72
};

// true if 'word' appears in 'text' as a whole word (case-insensitive): the characters
// before and after it must not be letters or digits, so KF0WXX doesn't match KF0WXXX.
static bool containsWordNoCase(const char* text, const char* word) {
  size_t n = strlen(word);
  if (n == 0 || text == NULL) return false;
  for (const char* h = text; *h; h++) {
    if (h != text && isalnum((unsigned char)h[-1])) continue;
    size_t i = 0;
    while (i < n && h[i] && tolower((unsigned char)h[i]) == tolower((unsigned char)word[i])) i++;
    if (i == n && !isalnum((unsigned char)h[n])) return true;
  }
  return false;
}

// CRC-16/CCITT-FALSE
static uint16_t crc16(const uint8_t* data, size_t len, uint16_t crc = 0xFFFF) {
  while (len--) {
    crc ^= (uint16_t)(*data++) << 8;
    for (int b = 0; b < 8; b++) crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
  }
  return crc;
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
  _prefs.id_off = 0;
  _prefs.id_interval_secs = HAM_ID_INTERVAL_SECS;
  _n_pub = _n_enc = _n_ids = _n_vetoed = 0;
  _load_failed = false;
  _last_id_ms = _id_queued_ms = 0;
  _pub_since_id = false;
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

// Reads one prefs file into 'out'. Returns 0 = missing/unreadable/corrupt,
// 1 = old v1 file (no checksum), 2 = valid v2 file (checksum OK).
static int readPrefsFile(FILESYSTEM* fs, const char* path, HamTxPrefs& out) {
  if (!fs->exists(path)) return 0;
#if defined(RP2040_PLATFORM)
  File file = fs->open(path, "r");
#else
  File file = fs->open(path);
#endif
  if (!file) return 0;
  uint8_t hdr[2];
  uint8_t crc_bytes[2];
  int result = 0;
  if (file.read(hdr, 2) == 2 && hdr[0] == HAM_PREFS_MAGIC
      && file.read((uint8_t*)&out, sizeof(out)) == sizeof(out)) {
    if (hdr[1] == HAM_PREFS_VERSION) {
      if (file.read(crc_bytes, 2) == 2) {
        uint16_t stored = crc_bytes[0] | (crc_bytes[1] << 8);
        uint16_t calc = crc16((const uint8_t*)&out, sizeof(out), crc16(hdr, 2));
        if (stored == calc) result = 2;
      }
    } else if (hdr[1] == 1) {
      result = 1;   // legacy, written by earlier MeshCore-Ham builds
    }
  }
  file.close();
  return result;
}

static bool writePrefsFile(FILESYSTEM* fs, const char* path, const HamTxPrefs& prefs) {
  File file = openWrite(fs, path);
  if (!file) return false;
  uint8_t hdr[2] = { HAM_PREFS_MAGIC, HAM_PREFS_VERSION };
  uint16_t crc = crc16((const uint8_t*)&prefs, sizeof(prefs), crc16(hdr, 2));
  uint8_t crc_bytes[2] = { (uint8_t)(crc & 0xFF), (uint8_t)(crc >> 8) };
  bool ok = file.write(hdr, 2) == 2;
  ok = ok && file.write((const uint8_t*)&prefs, sizeof(prefs)) == sizeof(prefs);
  ok = ok && file.write(crc_bytes, 2) == 2;
  file.close();
  return ok;
}

void HamTxPolicy::load(FILESYSTEM* fs) {
  HamTxPrefs tmp;
  int kind = readPrefsFile(fs, HAM_PREFS_FILE, tmp);
  bool from_backup = false;
  if (kind != 2) {
    HamTxPrefs bak;
    if (readPrefsFile(fs, HAM_PREFS_BACKUP, bak) == 2) {   // main file damaged (e.g. power lost mid-save)
      tmp = bak; kind = 2; from_backup = true;
    }
  }
  if (kind == 0) {
    // Missing or corrupt with no good backup: keep defaults, and if a file WAS there,
    // make sure ham mode stays OFF rather than trusting anything in it.
    if (fs->exists(HAM_PREFS_FILE) || fs->exists(HAM_PREFS_BACKUP)) {
      _prefs.enabled = 0;
      _load_failed = true;
    }
    return;
  }
  tmp.callsign[sizeof(tmp.callsign) - 1] = 0;
  for (int i = 0; i < HAM_MAX_TAGS; i++) tmp.tags[i][HAM_TAG_MAX_LEN - 1] = 0;
  tmp.pub_dbm = constrain(tmp.pub_dbm, -9, 30);
  tmp.enc_dbm = constrain(tmp.enc_dbm, -9, 30);
  if (tmp.enabled > 1) tmp.enabled = 0;
  if (tmp.id_off > 1) tmp.id_off = 0;
  if (tmp.id_interval_secs < 60 || tmp.id_interval_secs > 600) tmp.id_interval_secs = HAM_ID_INTERVAL_SECS;
  _prefs = tmp;
  rebuildKeys();
  if (kind == 1 || from_backup) save(fs);   // upgrade old file / repair main file
}

bool HamTxPolicy::save(FILESYSTEM* fs) {
  // Two copies: if power is lost while writing one, the other is still valid.
  bool ok = writePrefsFile(fs, HAM_PREFS_FILE, _prefs);
  ok = writePrefsFile(fs, HAM_PREFS_BACKUP, _prefs) && ok;
  if (ok) _load_failed = false;
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
  if (!containsWordNoCase(node_name, _prefs.callsign)) return "name lacks callsign";
  return NULL;
}

bool HamTxPolicy::isActive(const char* node_name) const {
  return inactiveReason(node_name) == NULL;
}

bool HamTxPolicy::isSelfAdvert(const mesh::Packet* pkt) const {
  return _self_pub_key && pkt->getPayloadType() == PAYLOAD_TYPE_ADVERT
      && pkt->payload_len >= PUB_KEY_SIZE
      && memcmp(pkt->payload, _self_pub_key, PUB_KEY_SIZE) == 0;
}

int8_t HamTxPolicy::selectPower(const mesh::Packet* pkt, const char* node_name, int8_t default_dbm, unsigned long now_ms, bool& must_apply) {
  must_apply = false;
  if (isSelfAdvert(pkt)) {
    // every advert of ours carries our name (and callsign): restart the station ID timer
    _last_id_ms = now_ms;
    _id_queued_ms = 0;
    _pub_since_id = false;
    if (isActive(node_name)) _n_ids++;
  }
  if (!isActive(node_name)) return default_dbm;
  if (classify(pkt) == HAM_TX_ENCRYPTED) {
    _n_enc++;
    must_apply = true;   // never let encrypted traffic go out at whatever power the radio was left at
    return _prefs.enc_dbm;
  }
  _n_pub++;
  if (!isSelfAdvert(pkt)) _pub_since_id = true;
  return _prefs.pub_dbm;
}

bool HamTxPolicy::isStationIdDue(const char* node_name, unsigned long now_ms) {
  if (_prefs.id_off || !_pub_since_id || !isActive(node_name)) return false;
  if (_id_queued_ms) {
    if (now_ms - _id_queued_ms < 60000UL) return false;   // still waiting to go out
    _id_queued_ms = 0;                                    // got lost, try again
  }
  return now_ms - _last_id_ms >= (unsigned long)_prefs.id_interval_secs * 1000UL;
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

// Explains why ham mode is WAITING on the callsign/name check (reply < 160 chars).
void HamTxPolicy::nameProblem(char* reply, const char* prefix, const char* advert_name, const char* full_name) const {
  if (containsWordNoCase(full_name, _prefs.callsign)) {
    // in the name, but cut off (or split) in what adverts actually send
    sprintf(reply, "%s%s gets cut off in adverts (they send '%s'). Put it first: set name %s ...",
      prefix, _prefs.callsign, advert_name, _prefs.callsign);
  } else {
    sprintf(reply, "%snode name must include %s as its own word. Type: set name %s ...",
      prefix, _prefs.callsign, _prefs.callsign);
  }
}

bool HamTxPolicy::handleCommand(const char* command, char* reply, const char* node_name, const char* full_name, bool& dirty) {
  dirty = false;
  if (full_name == NULL) full_name = node_name;
  const char* p = command;
  if (!takeWord(p, "ham")) return false;

  // NOTE: CLI reply buffers are ~160 chars, keep every reply shorter than that.

  if (*p == 0 || takeWord(p, "status")) {
    const char* why = inactiveReason(node_name);
    int n = 0;
    for (int i = 0; i < HAM_MAX_TAGS; i++) if (_prefs.tags[i][0]) n++;
    if (why == NULL) {
      char id_str[12];
      if (_prefs.id_off) strcpy(id_str, "off");
      else sprintf(id_str, "%u min", (_prefs.id_interval_secs + 30) / 60);
      sprintf(reply, "ON - callsign %s, public power %d, private power %d, extra channels %d, ID %s",
        _prefs.callsign, _prefs.pub_dbm, _prefs.enc_dbm, n, id_str);
    } else if (!_prefs.enabled) {
      sprintf(reply, "OFF - all packets use normal 'tx' power. Type: ham on");
    } else if (_prefs.callsign[0] == 0) {
      strcpy(reply, "WAITING - no callsign set. Type: ham callsign YOURCALL");
    } else {
      nameProblem(reply, "WAITING - ", node_name, full_name);
    }
    if (_load_failed && strlen(reply) < 110) strcat(reply, " (settings file was damaged - re-enter settings)");
    if (_n_vetoed > 0 && strlen(reply) < 100) {
      char w[80];
      sprintf(w, " WARNING: %lu private pkts blocked, radio rejected power %d", (unsigned long)_n_vetoed, _prefs.enc_dbm);
      strcat(reply, w);
    }

  } else if (takeWord(p, "help")) {
    strcpy(reply, "ham on|off, ham callsign X, ham public N, ham private N, ham id on|off|N, "
                  "ham channel add #x, ham channel remove #x, ham channels, ham stats");

  } else if (takeWord(p, "on")) {
    _prefs.enabled = 1; dirty = true;
    const char* why = inactiveReason(node_name);
    if (why == NULL) strcpy(reply, "OK - ham mode ON");
    else if (_prefs.callsign[0] == 0) strcpy(reply, "OK - but still WAITING: set callsign with 'ham callsign YOURCALL'");
    else nameProblem(reply, "OK - but WAITING: ", node_name, full_name);

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
        if (containsWordNoCase(node_name, _prefs.callsign)) sprintf(reply, "OK - callsign set to %s", _prefs.callsign);
        else nameProblem(reply, "OK - but ", node_name, full_name);
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

  } else if (takeWord(p, "id")) {
    if (*p == 0) {
      if (_prefs.id_off) strcpy(reply, "station ID is off");
      else sprintf(reply, "station ID: advert every %u min while sending public traffic", (_prefs.id_interval_secs + 30) / 60);
    } else if (takeWord(p, "off")) {
      _prefs.id_off = 1; dirty = true;
      strcpy(reply, "OK - station ID off. Only your normal adverts will go out");
    } else if (takeWord(p, "on")) {
      _prefs.id_off = 0; dirty = true;
      sprintf(reply, "OK - station ID on, every %u min while sending public traffic", (_prefs.id_interval_secs + 30) / 60);
    } else {
      int mins = (*p >= '0' && *p <= '9') ? atoi(p) : 0;
      if (mins < 1 || mins > 10) {
        strcpy(reply, "Error: use 'ham id on', 'ham id off', or 'ham id N' (N = 1 to 10 minutes)");
      } else {
        _prefs.id_interval_secs = (mins == 10) ? 570 : mins * 60;   // 10 -> 9.5 min, keeps margin under the 10 min rule
        dirty = true;
        sprintf(reply, "OK - station ID every %d min while sending public traffic", mins);
      }
    }

  } else if (takeWord(p, "stats")) {
    sprintf(reply, "Sent since boot: %lu public, %lu private, %lu IDs, %lu blocked (power change failed)",
      (unsigned long)_n_pub, (unsigned long)_n_enc, (unsigned long)_n_ids, (unsigned long)_n_vetoed);

  } else {
    strcpy(reply, "Unknown ham command. Type: ham help");
  }
  return true;
}
