# intel-kit download service API contract (v1) — shared by Worker, bootstrap, updater, intel-admin

Base URL: env INTEL_KIT_API, else constant DEFAULT_API = "https://intel-kit-dl.REPLACE_ME.workers.dev" (set in phase 2).
All bodies JSON UTF-8. Error body: {"error": "<code>", "message": "<plain Chinese>"}.

## POST /v1/activate
Request: {"license_key": "IK-XXXX-XXXX-XXXX-XXXX", "device_fingerprint": "<64 hex sha256>", "client": "bootstrap/0.1.0", "current_version": "0.1.0"|null}
Checks in order: key format (400 bad_request) → key hash lookup (401 invalid_key) → status revoked (403 revoked)
→ device: if fingerprint not yet registered and registered devices >= max_devices (default 3) → 403 device_limit, else register/touch
→ entitled release = newest release with released_at <= update_expires_at (or newest if update_expires_at null); none → 404 no_release;
  if a newer release exists but is not entitled, include "update_rights_expired": true
→ daily cap: downloads for this license in the current UTC day >= daily_cap (default 10) → 429 daily_cap
→ log download row; respond 200:
{"license_id":"lic_...","version":"0.1.0","schema_version":1,"sha256":"<hex>","size":123,
 "package_url":"<abs url>","signature_url":"<abs url>","expires_at":"<ISO UTC, now+600s>",
 "update_expires_at":"<ISO>"|null,"update_rights_expired":false}

## GET /v1/latest
Headers: X-License-Key, X-Device-Fingerprint. Same key/revoked checks; device must already be registered (403 device_not_activated).
200 {"version","schema_version","sha256","size","released_at","update_rights_expired":bool}. Does not count toward daily cap.

## GET /v1/dl/{version}/{file}?lic=<license_id>&exp=<unix seconds>&sig=<hex>
file ∈ {"package.tar.gz","package.tar.gz.minisig"}. sig = hex(HMAC-SHA256(URL_SIGNING_SECRET, `${version}|${file}|${lic}|${exp}`)).
Expired → 410 link_expired; bad sig → 403 bad_signature; license revoked since → 403 revoked. Streams the R2 object
`releases/{version}/{file}`. Response header X-Intel-Kit-License: <license_id>.

## Admin (Authorization: Bearer <ADMIN_TOKEN>, constant-time compare; missing/wrong → 401)
- POST /v1/admin/licenses {"label": "...", "max_devices"?: 3, "daily_cap"?: 10, "update_months"?: 12} → 201 {"license_id","license_key" (shown once),"update_expires_at"}
- POST /v1/admin/licenses/{license_id}/revoke → 200 {"license_id","status":"revoked"}
- GET /v1/admin/licenses → 200 {"licenses":[{license_id,label,status,max_devices,daily_cap,update_expires_at,created_at,revoked_at,devices,downloads_today}]} (never key or hash)
- POST /v1/admin/releases {"version","schema_version","sha256","size","released_at"?} → 201 (R2 objects must already exist: releases/{version}/package.tar.gz and .minisig; else 409 missing_object)
- GET /v1/admin/releases → list

## Storage
Keys stored as hex(HMAC-SHA256(KEY_PEPPER, license_key)). Device fingerprints stored as hex(HMAC-SHA256(KEY_PEPPER, fp)).
Secrets (Worker secrets, never in repo): ADMIN_TOKEN, KEY_PEPPER, URL_SIGNING_SECRET.

## Package
package.tar.gz contains a single top dir `intel-kit-<version>/` (with VERSION, bin/intel, src/, presets/, ... ) and
`intel-kit-<version>/manifest.json` = {"version","schema_version","built_at"}. Signed with minisign (prehashed, "ED").
Release public key (embedded in bootstrap and updater):
RWS5EBqsqD2Wxxb5n6/8HmrpgL8hXrSKuTK3nj/Ur2vSB7i6zYIL+giq

## Device fingerprint (client)
sha256 hex of "intel-kit|" + platform.system() + "|" + platform.machine() + "|" + machine_id + "|" + getpass.getuser(),
machine_id = macOS `ioreg -rd1 -c IOPlatformExpertDevice` IOPlatformUUID; Linux /etc/machine-id or /var/lib/dbus/machine-id;
Windows HKLM\SOFTWARE\Microsoft\Cryptography MachineGuid; fallback uuid.getnode(). Only the hash leaves the machine.
