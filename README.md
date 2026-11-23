# MeshCore Ham Firmware

**Stock MeshCore v1.18.0, plus one feature:** the radio uses a different transmit power depending on whether a packet is **public** (anyone can read it) or **private** (encrypted).

That lets a licensed amateur radio operator send public traffic at **ham power** while private, encrypted traffic stays at a lower **unlicensed (Part 15) power**.

- Works on **repeaters** and **room servers**, on every board stock MeshCore supports.
- Fully compatible with stock MeshCore nodes and apps. Nothing changes for anyone else on the mesh.
- **Off until you turn it on.** Until then, it behaves exactly like stock MeshCore.

> This is a community fork of [MeshCore](https://github.com/meshcore-dev/MeshCore). The original MeshCore README is in [README-MeshCore.md](README-MeshCore.md).

---

## Contents

1. [How it works](#how-it-works)
2. [What counts as public and what counts as private](#what-counts-as-public-and-what-counts-as-private)
3. [Station ID (automatic)](#station-id-automatic)
4. [Install the firmware](#install-the-firmware)
5. [Set it up (5 steps)](#set-it-up-5-steps)
6. [Command list](#command-list)
7. [Check that it's working](#check-that-its-working)
8. [Troubleshooting & FAQ](#troubleshooting--faq)
9. [Other differences from stock MeshCore](#other-differences-from-stock-meshcore)
10. [Your responsibility](#your-responsibility)

---

## How it works

Right before your node sends **any** packet, the firmware looks at what kind of packet it is:

```
            packet about to be sent
                      │
        Can anyone on the mesh read it?
             │                   │
            YES                  NO
             │                   │
     PUBLIC power          PRIVATE power
   (e.g. ham power)      (e.g. Part 15 power)
```

This includes packets your node is only **passing along** for other people, which is most of what a repeater sends.

If the firmware can't tell for sure that a packet is public, it treats it as **private**. That's the safe choice.

**Built-in safety checks:**

- **Your callsign must really go out on air.** Adverts only have room for the first 31 characters of the node name (23 if you share your location). Ham mode only switches on if your callsign is inside the part adverts actually send, and it has to be a whole word, so `KF0WXX` doesn't count inside `KF0WXXX`.
- **Private packets never go out at the wrong power.** The firmware sets the power before every packet. If the radio refuses the private power level, that private packet is **dropped instead of sent**, and `ham` shows a warning.
- **Damaged settings turn ham mode off.** Settings are saved twice with a checksum. If one copy gets damaged (for example by a power cut while saving), the other is used. If both are damaged, ham mode stays **OFF** until you set it up again.

---

## What counts as public and what counts as private

| Sent at **PUBLIC** power | Sent at **PRIVATE** power |
|---|---|
| Messages on the **Public** channel | **Direct messages** (DMs) between two people |
| Messages on **#hashtag channels you add** to the list | Messages on **private channels** (ones with a secret key) |
| **Adverts** (a node announcing itself) | **#hashtag channels you have NOT added** |
| **ACKs** (delivery receipts) | Logins, requests and replies (e.g. remote admin) |
| **Traces** and **discovery** packets | Path updates, custom data, anything unrecognized |

**Why is the Public channel "public" if MeshCore encrypts it?**
The Public channel's key is published for everyone, so anyone can read it. The same goes for #hashtag channels: the key comes from the channel name, so anyone who knows the name can read them.

**Why only the #hashtag channels I add?**
The firmware can only check a #hashtag channel if it knows the channel's name. So you list the ones you want sent at public power.

The firmware also checks each message against the real key before calling it public. A private channel that happens to look like the Public channel still goes out at private power.

---

## Station ID (automatic)

Every MeshCore advert carries your node's name, and your name includes your callsign, so **an advert works as your station ID.**

While ham mode is **ON**, the firmware makes sure your callsign goes out regularly:

```
   public traffic sent ──► has it been 9 minutes since our last advert?
                                 │                     │
                                YES                    NO
                                 │                     │
                     send a zero-hop advert       wait, check again
                       (= station ID)
```

- **Any advert resets the timer.** That includes your scheduled ones, the ones you send by hand, and the automatic ID itself. So if your node adverts at the end of a burst of traffic, the clock starts over from there.
- **Quiet node = no extra adverts.** If your node hasn't sent anything at public power since its last advert, it doesn't send an ID. An idle repeater adds zero traffic.
- **Busy node = one short advert every 9 minutes at most.** It's a zero-hop advert, so only your direct neighbours hear it and nobody repeats it.
- **Why 9 minutes and not 10?** The rule is "at least every 10 minutes." 9 minutes leaves room for the advert to wait its turn on a busy channel and still go out in time. Change it with `ham id N` (1 to 10 minutes). Choosing 10 actually uses 9.5 minutes for the same reason.
- **Private-only traffic never triggers an ID**, because it's sent at unlicensed power.

Don't want it? `ham id off` turns it off, and then only your normal adverts go out.

---

## Install the firmware

### Option A: Download a ready-made file (easiest)

1. Go to this repository's **[Releases](../../releases)** page.
2. Download the file for your board. Look for `_repeater` or `_room_server` in the name, for example `Station_G3_ESP32_repeater-....bin`.
   - **ESP32 boards** (Heltec V3/V4, Station G2/G3, T-Beam, ...):
     - Use the `-merged.bin` file for a first install or a full wipe.
     - Use the plain `.bin` to update a board that already runs MeshCore.
   - **nRF52 boards** (RAK4631, T-Echo, ...): use the `.uf2` file. Double-tap the reset button so the board shows up as a USB drive, then drag the file onto it.
3. ESP32 boards: flash the `.bin` with a browser tool such as [Adafruit ESPTool](https://adafruit.github.io/Adafruit_WebSerial_ESPTool/). Flash a `-merged.bin` at address `0x0`. nRF52 boards: drag the `.uf2` as described above.

### Option B: Build it yourself in VS Code

1. Install [VS Code](https://code.visualstudio.com/) and the **PlatformIO IDE** extension.
2. Download this repository: click the green **Code** button, then **Download ZIP**, and unzip it. Or clone it with git.
3. In VS Code, choose **File → Open Folder** and pick the unzipped folder. The first time, PlatformIO takes a few minutes to download its tools.
4. Click the **PlatformIO icon** (the ant head) on the left sidebar.
5. Find your board's repeater or room server, for example **`Station_G3_ESP32_repeater`**, and click **Build**.
6. Plug the board in by USB and click **Upload**.
   - If the upload can't connect on an ESP32 board, hold the **BOOT** button while plugging in the USB cable, then try again.

Your settings are **kept** when you update. Ham settings are saved in their own file, so going back to stock MeshCore is also safe.

---

## Set it up (5 steps)

Connect to the node's **serial console**. Use any serial terminal at 115200 baud, PlatformIO's **Monitor** button, or log in as admin from the MeshCore app's remote management. Then type:

**1. Put your callsign in the node's name, near the start.**
Adverts carry the node name, so this is how your node identifies itself on air. Adverts cut long names short (31 characters, or 23 with location), so put the callsign first.
```
set name KF0WXX Waverly
```

**2. Tell the firmware your callsign.**
```
ham callsign KF0WXX
```

**3. Set the two power levels.**
These use the same numbers as the normal `set tx` command.
```
ham public 22
ham private 15
```

**4. (Optional) Add any #hashtag channels that should use public power.**
```
ham channel add #nebraska
```

**5. Turn it on and check.**
```
ham on
ham
```
You should see:
```
ON - callsign KF0WXX, public power 22, private power 15, extra channels 1, ID 9 min
```

If you see **`WAITING`** instead, the message says exactly what's missing. See [Troubleshooting](#troubleshooting--faq).

---

## Command list

All commands start with `ham`. They work over the serial console and over remote admin. Every change is **saved immediately** and kept through reboots and firmware updates.

| Command | What it does | Example |
|---|---|---|
| `ham` | Shows whether ham mode is **ON**, **OFF** or **WAITING**, plus your current settings. | `ham` |
| `ham help` | Lists all the ham commands. | `ham help` |
| `ham on` | Turns ham mode on. | `ham on` |
| `ham off` | Turns ham mode off. Every packet then uses the normal `set tx` power, just like stock MeshCore. | `ham off` |
| `ham callsign CALL` | Sets your callsign. It must also be part of the node name. Type `ham callsign` alone to see the current one. | `ham callsign KF0WXX` |
| `ham public N` | Sets the power for **public** packets. N is -9 to 30, same as `set tx`. Type `ham public` alone to see the current value. | `ham public 22` |
| `ham private N` | Sets the power for **private** (encrypted) packets. N is -9 to 30. Type `ham private` alone to see the current value. | `ham private 15` |
| `ham channel add #name` | Sends that #hashtag channel at **public** power. Up to 8 channels. | `ham channel add #nebraska` |
| `ham channel remove #name` | Takes a #hashtag channel off the list. It goes back to **private** power. | `ham channel remove #nebraska` |
| `ham channels` | Lists every channel that uses public power. | `ham channels` |
| `ham id` | Shows the station ID setting. | `ham id` |
| `ham id N` | Sends a station ID advert every N minutes (1 to 10) while you're sending public traffic. Default 9. | `ham id 9` |
| `ham id off` / `ham id on` | Turns the automatic station ID off or back on. | `ham id off` |
| `ham stats` | Shows how many public and private packets and IDs were sent since the last reboot, and how many private packets were blocked because the radio refused the private power. | `ham stats` |

**What the status words mean:**

| Status | Meaning |
|---|---|
| **ON** | Working. Public and private packets use their own power levels. |
| **OFF** | Turned off with `ham off` (or never turned on). Every packet uses the normal `set tx` power. |
| **WAITING** | You typed `ham on`, but something is missing: no callsign is set, the node name doesn't include the callsign as its own word, or the callsign gets cut off in adverts. Until you fix it, every packet uses the normal `set tx` power. |

<details>
<summary>Older command names (still work)</summary>

| Old | New |
|---|---|
| `ham call` | `ham callsign` |
| `ham pub` | `ham public` |
| `ham enc` | `ham private` |
| `ham tag add` / `ham tag del` | `ham channel add` / `ham channel remove` |
| `ham tags` | `ham channels` |
| `ham status` | `ham` |

</details>

---

## Check that it's working

1. Type `ham` and make sure it says **ON**.
2. Send one message on the **Public** channel and one **direct message** through the node.
3. Type `ham stats`. Both the **public** and **private** counts should have gone up.
4. If you have a power meter or SDR, you should see two different output levels.

---

## Troubleshooting & FAQ

**`ham` says `WAITING - no callsign set`**
Run `ham callsign YOURCALL`.

**`ham` says `WAITING - node name must include ...`**
The node name has to contain your callsign as its own word, for example `set name KF0WXX Waverly`. Upper or lower case doesn't matter.

**`ham` says `... gets cut off in adverts`**
Your name is too long, so adverts drop the end of it, including your callsign. Move the callsign to the start: `set name KF0WXX Waverly Backbone`.

**`ham` shows `WARNING: ... private pkts blocked`**
The radio refused your private power setting, so the node dropped those private packets rather than risk sending them at ham power. Pick a value your board supports, for example `ham private 10`.

**`ham` says `settings file was damaged`**
Both saved copies of the ham settings were damaged, so ham mode was switched off for safety. Set it up again (callsign, powers, channels, `ham on`).

**My node sends more adverts than before.**
That's the automatic station ID. A busy node sends at most one zero-hop advert every 9 minutes. Use `ham id 10` for a little less, or `ham id off` to turn it off.

**My #hashtag channel still goes out at private power.**
- Check `ham channels` to see whether it's on the list.
- The name must match the app **exactly**, including capital letters: `#Nebraska` and `#nebraska` are different channels.

**My board has an amplifier (Station G2/G3, 1 W boards). Are the numbers the real output power?**
No. On those boards, the number is the drive level going into the amplifier, exactly like the normal `set tx`. Measure the real output with a meter and pick your two numbers from that.

**Does this work on companion radios (the one paired to my phone)?**
No, only repeaters and room servers. Your companion sends at its own normal power. Any repeater running this firmware still applies the public/private split when it **passes along** your companion's packets.

**Will this confuse stock MeshCore nodes or apps?**
No. Only the transmit power changes. The packets themselves are exactly the same.

**How do I go back to stock behavior?**
Type `ham off`, or flash stock MeshCore. Your normal settings are not affected.

---

## Other differences from stock MeshCore

These are small changes that came up while running this firmware on a real network:

- **Zero-hop advert interval defaults to 240 minutes** on new installs. The flood advert stays at 47 hours. Stock MeshCore sends a zero-hop advert every 2 minutes until you change it. Change yours any time with `set advert.interval` and `set flood.advert.interval`.
- **Zero-hop adverts carry your 2- or 3-byte path setting.** In stock MeshCore, only flood adverts carry the `set path.hash.mode` setting, so zero-hop adverts always showed up as "1 byte" in analyzers. Now both kinds carry your setting.
- **Automatic station ID** (only while ham mode is ON): a zero-hop advert at most every 9 minutes, only while you're sending public traffic. See [Station ID](#station-id-automatic).

`ver` shows the firmware version as **`v1.18.0-ham`**.

---

## Your responsibility

This firmware gives you the tools; how you use them is up to you. **It is not legal advice.**

- Using ham power requires an amateur license. You, as the control operator, are responsible for following your country's rules. That includes station identification and what may and may not be encrypted.
- Choose your private power level carefully, based on the unlicensed rules that apply where you are.
- Classifying a packet as public or private is a best effort. It follows the table above.

---

### Credits & license

Based on [MeshCore](https://github.com/meshcore-dev/MeshCore) by the MeshCore developers. MIT License, see [license.txt](license.txt).
Ham power feature by KF0WXX for the [Nebraska Mesh](https://nebraskamesh.net) community.
The whole-word callsign check, the advert-name length check, blocking private packets when the radio rejects a power change, and checksummed settings were inspired by [jhuebert's repeater-filter firmware](https://github.com/jhuebert/MeshCore), which adapted this ham mode.

<details>
<summary>For developers: where the code lives</summary>

- `src/helpers/HamTxPolicy.h` / `.cpp`: decides public or private for each packet, the `ham` commands, and saving settings (to `/ham_prefs` + `/ham_prefs.bak`, each with a CRC-16).
- `src/helpers/radiolib/RadioLibWrappers.*`: `lastTxPowerOk()` reports whether the radio accepted the last power change.
- `src/Dispatcher.h` / `.cpp`: adds the `onBeforeTransmit()` hook, which runs just before each packet is sent and can drop it by returning `false`.
- `src/Mesh.h` / `.cpp`: `sendZeroHop()` takes an optional path hash size.
- `examples/simple_repeater/MyMesh.*`, `examples/simple_room_server/MyMesh.*`: connect the pieces together.

Optional build flags to pre-load settings on fresh installs: `-D HAM_ENABLED=1`, `-D HAM_CALLSIGN='"KF0WXX"'`, `-D HAM_PUB_TX_POWER=22`, `-D HAM_ENC_TX_POWER=15`, `-D HAM_ID_INTERVAL_SECS=540`, `-D HAM_MAX_TAGS=8`.

</details>
