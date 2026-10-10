> English translation of docs/04-device-setup.md. The Chinese original is authoritative.

# 04 · Signer Device Setup Procedure

Status: P0 draft · 2026-10-10 · to be revised after P1 real-device testing

> The order must not be changed. **No seed may appear on the iPhone before step 6.**

## What you need

- 1 dedicated iPhone (a model still supported by iOS updates)
- 1 Mac for building (with Xcode installed; see `toolchain/TOOLCHAIN.lock`)
- A paid Apple Developer account (development certificates are valid for 1 year; free accounts expire after 7 days and are not suitable)
- A data cable (original or MFi-certified)

## Steps

1. **Erase the iPhone**: Settings → General → Transfer or Reset iPhone → Erase All Content and Settings.
2. **Activation** (this step requires a network connection; this cannot be avoided):
   - Do not sign in with an Apple ID (choose "Forgot password or don't have an Apple ID?" → "Set Up Later in Settings")
   - Turn off: Location Services, Siri, Screen Time, Analytics & Improvements, iCloud
   - Set a device passcode of 6 or more digits
3. **Register the device**: on the Mac, connect the iPhone via Xcode → Window → Devices and Simulators, and add the device to the developer account.
4. **Developer Mode**: on the iPhone, Settings → Privacy & Security → Developer Mode → turn on → restart → enter the passcode to confirm.
5. **Install and trust** (the iPhone is still online at this point):
   - On the Mac, build Signer from source and install it over the data cable (see `ios/Signer/README.md`)
   - If prompted with "Untrusted Developer": Settings → General → VPN & Device Management → Trust
   - Open Signer once to confirm that it launches
6. **Go permanently offline**:
   - Remove the SIM card / delete the eSIM
   - Settings → Wi-Fi → off; Settings → Bluetooth → off (turning them off in Control Center does not fully disable them)
   - Turn on Airplane Mode, and confirm that Wi-Fi and Bluetooth remain off while in Airplane Mode
   - Settings → General → AirDrop → Receiving Off
   - Optional: turn on Lockdown Mode (compatibility with Signer to be verified in P1)
7. **Only then** generate or import a seed in Signer.

## Ongoing discipline

- Never connect to any Wi-Fi, never insert a SIM, never connect to a computer (except to upgrade Signer, and even then stay offline)
- Power it off when not in use and keep it in a Faraday bag
- Upgrading Signer: build on the Mac while offline → install over the data cable → verify the version hash inside Signer

## Questions that must be tested on real devices in P1

| ID | Question | Method | Pass criterion |
|---|---|---|---|
| D1 | After the developer certificate is trusted, does the app keep launching over the long term while offline? | After setting up per the procedure above, go offline and launch once each on days 1, 7, 30, 60, and 90 | Launches every time |
| D2 | Can it launch offline after a restart? | While offline, power off and restart, then open Signer | Launches |
| D3 | Does Lockdown Mode affect developer-signed apps? | Launch after turning on Lockdown Mode | Launches |
| D4 | Is upgrading Signer over the data cable feasible while offline? | With the Mac offline, install the new version with Xcode | Installs and launches |

If D1 or D2 fails: go to a design review (alternatives: switch to App Store/TestFlight distribution and give up verifiability; or use dedicated hardware for the Signer instead).
