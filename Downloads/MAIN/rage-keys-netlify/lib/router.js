"use strict";

// the whole api, written against plain objects instead of node's http streams:
//
//   handle({ route, method, headers, body, ip }) -> { status, headers, body }
//
// the Netlify function and dev-server.js both call this, so what you test at
// home is the same code Netlify runs.

const crypto = require("node:crypto");
const store = require("./store");
const license = require("./license");
const webhook = require("./webhook");
const lootlabs = require("./lootlabs");
const bypass = require("./bypass");
const seal = require("./seal");
const cloudConfig = require("./cloud-config");

const VERSION = "3.4.0";
const MINUTE = license.MINUTE;
const HOUR = license.HOUR;
const DAY = license.DAY;

// "6h" for a short extension, "2d" when it lands on whole days
function roundHours(hours) {
  if (hours >= 24 && hours % 24 === 0) return hours / 24 + "d";
  return Math.round(hours * 100) / 100 + "h";
}
const CLAIM_TTL_MS = 2 * HOUR;
// an api-made anti-bypass link does not live long - the provider retires the task
// behind it, and a visitor who clicks an old one lands on its "link not found" page
// with nothing they can do about it. ten minutes keeps the cached link well inside
// that, and the claim page asks for a fresh one at the moment it is opened, so the
// window a visitor can hit is as small as it can be without a link per page load
const CLAIM_LINK_TTL_MS = 10 * MINUTE;
// a claim walks the visitor through this many monetized lockers: one link, a stop
// back on this site, the next link, and so on. each link carries a token for its
// own step, so a later one cannot be opened - and its return cannot be faked -
// without every visit before it having come back.
// two, not three: the anti-bypass layer treats a second completion from the same
// visitor as a bypass attempt, so a third locker would cost real keys. raising
// this again means changing it here and nothing else - the page reads the steps
// from the server.
const CLAIM_STEPS = 2;

// one request can touch several things at once; this is how many of those the
// owner's webhook hears about, so a slow endpoint cannot stall the script
const WEBHOOK_MAX_PER_REQUEST = 3;

// per instance and therefore best effort - the limits that must hold (claim
// cooldown, daily cap, device locks) live in the stored document instead
const limiter = new license.Limiter();

// the routes the script itself calls. everything it sends is sealed, and while
// `sealed only` is on these are the only places anything else is turned away:
// the claim flow and the panel are browser routes and stay as they are.
const SEALED_ROUTES = new Set([
  "v1/auth",
  "v1/heartbeat",
  "v1/console",
  "v1/command/done",
  "v1/unbind",
]);

// filled by record() while a request runs, delivered in the same request
let pendingWebhooks = [];

// the caller of the request being handled, so every event can carry the address
// it came from without each call site passing it
let caller = { ip: "", ua: "" };

// ------------------------------------------------------------------ helpers
function stamp() {
  return new Date().toTimeString().slice(0, 8);
}

function record(type, message, extra) {
  const number = (value, size) => String(value || "").slice(0, size);
  const line = {
    type: String(type).toUpperCase(),
    message: message === undefined || message === null ? "" : String(message),
    ...(extra || {}),
  };

  // an owner action or a generated key has no ip of its own, but it happened
  // because somebody called in: that address belongs on the line
  if (!line.ip && caller.ip) line.ip = caller.ip;
  if (!line.ua && caller.ua) line.ua = caller.ua;

  store.pushEvent(line);

  // the webhook's own delivery report is not forwarded, and neither is anything
  // past the cap above
  if (line.type !== "WEBHOOK" && pendingWebhooks.length < WEBHOOK_MAX_PER_REQUEST) {
    pendingWebhooks.push(line);
  }

  const bits = [stamp(), line.type.padEnd(8), line.message];
  if (line.key) bits.push("key=" + line.key);
  if (line.hwid) bits.push("hwid=" + number(line.hwid, 12));
  if (line.executor) bits.push(number(line.executor, 24));
  if (line.ip) bits.push("ip=" + line.ip);
  console.log(bits.filter(Boolean).join(" "));
}

function userAgent(request) {
  return String((request.headers || {})["user-agent"] || "").slice(0, 160);
}

function originOf(request) {
  const headers = request.headers || {};
  return String(headers["origin"] || headers["referer"] || "").slice(0, 120);
}

// one row per live session: the identity (a key, or "keyless") plus the device
// running it, so beating again refreshes the row instead of adding another
function sessionFields(request, data, extra) {
  return {
    sid: String(extra.sid || "unknown") + "@" + license.hwidFingerprint(extra.hwid || "").slice(0, 12),
    keyId: extra.keyId || "",
    key: extra.key || "",
    plan: extra.plan || "",
    keyless: !!extra.keyless,
    hwid: extra.hwid || "",
    ip: clientIp(request),
    ua: userAgent(request),
    executor: String(data.executor || "").slice(0, 40),
    version: String(data.version || "").slice(0, 16),
    place: String(data.place || "").slice(0, 24),
    // the job id is what a join script needs besides the place id
    job: String(data.job || "").slice(0, 48),
    // what the client reports it is running at, so the panel shows the frame rate
    // of each session instead of leaving it to guesswork
    fps: Math.max(0, Math.min(1000, Math.round(Number(data.fps) || 0))),
    // memory in megabytes and the instance count, as the client reported them on
    // the beat that carried them. a session that is leaking is a rising number
    // here, which is the only way to tell a leak from a cost before it dies
    mem: Math.max(0, Math.min(65536, Math.round(Number(data.mem) || 0))),
    inst: Math.max(0, Math.min(100000000, Math.round(Number(data.inst) || 0))),
  };
}

// everything waiting for this device: lua to run, a message to show, a kick
function leaseExtras(sid) {
  return { commands: store.pendingCommands(sid) };
}

// the request log holds the calls that carry a key or change something. pings
// and claim status polls are skipped on purpose: logging those would be a blob
// write every few seconds for a script that is only saying it is still alive.
function logRequest(request, data, response, startedAt) {
  if (request.method !== "POST") return;
  if (store.settings().logRequests === false) return;
  // the clear button should leave an empty log, not a log holding itself
  if (request.route === "admin/activity/clear") return;

  let payload = {};
  try {
    payload = JSON.parse(response.body || "{}");
  } catch {
    payload = {};
  }

  store.pushRequest({
    at: Date.now(),
    ms: Date.now() - startedAt,
    route: request.route,
    status: response.status,
    ip: clientIp(request),
    ua: userAgent(request),
    origin: originOf(request),
    key: data.key ? shortKey(data.key) : "",
    hwid: data.hwid ? String(data.hwid).slice(0, 16) : "",
    executor: String(data.executor || "").slice(0, 40),
    version: String(data.version || "").slice(0, 16),
    place: String(data.place || "").slice(0, 24),
    code: String((payload && payload.code) || ""),
    reason: String((payload && payload.error) || "").slice(0, 120),
  });
}

// what a session printed, wherever it arrives. the beat carries it now, so one
// request does the work of two; the script's own console route still works, and is
// what gets a command's output back immediately
function storeLines(request, data, sid, hwid) {
  const raw = Array.isArray(data.lines) ? data.lines : [];
  if (!raw.length) return 0;

  const added = store.pushLines(sid, raw.slice(0, 40));
  if (!added) return 0;

  const preview = raw
    .map((line) => String(line).slice(0, 300))
    .slice(0, 12)
    .join(" | ");
  record("CONSOLE", `${added} console line${added === 1 ? "" : "s"}: ${preview}`, {
    hwid,
    ip: clientIp(request),
    ua: userAgent(request),
  });
  return added;
}

async function flushWebhooks() {
  const pending = pendingWebhooks;
  pendingWebhooks = [];

  const url = store.settings().webhookUrl;
  if (!url || !pending.length) return;

  const results = await Promise.all(
    pending.map((event) => webhook.deliver(url, event, { brand: store.settings().brand }))
  );

  for (const result of results) {
    const line = result.ok
      ? `delivered to ${result.host} (${result.status}, ${result.ms}ms)`
      : `delivery to ${result.host || "webhook"} failed - ${result.error}`;
    // this runs after the document was written and its lease handed back, so the
    // report cannot go into the state that was just saved. it is noted instead and
    // merged into the next write.
    store.noteEvent({ type: "WEBHOOK", message: line });
    console.log(stamp(), "WEBHOOK ", line);
  }
}

function reply(body, status, headers) {
  return {
    status: status || 200,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...(headers || {}),
    },
    body: JSON.stringify(body),
  };
}

function shortKey(raw) {
  const value = String(raw || "");
  return value ? value.slice(0, 4) + "..." + value.slice(-4) : "-";
}

function clientIp(request) {
  const headers = request.headers || {};
  const direct = String(headers["x-nf-client-connection-ip"] || "").trim();
  if (direct) return direct;
  const forwarded = String(headers["x-forwarded-for"] || "").split(",")[0].trim();
  return forwarded || String(request.ip || "unknown");
}

function cookies(request) {
  const raw = String((request.headers || {}).cookie || "");
  const out = {};
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    const name = part.slice(0, index).trim();
    if (!name) continue;
    try {
      out[name] = decodeURIComponent(part.slice(index + 1).trim());
    } catch {
      out[name] = part.slice(index + 1).trim();
    }
  }
  return out;
}

function parseBody(raw) {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    try {
      return Object.fromEntries(new URLSearchParams(raw));
    } catch {
      return {};
    }
  }
}

function compareVersions(left, right) {
  const a = String(left || "0").split(".").map((n) => parseInt(n, 10) || 0);
  const b = String(right || "0").split(".").map((n) => parseInt(n, 10) || 0);
  for (let index = 0; index < Math.max(a.length, b.length); index++) {
    const x = a[index] || 0;
    const y = b[index] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

// ---------------------------------------------------------------- key store
function findKey(raw) {
  const normalized = license.normalizeKey(raw);
  if (!normalized) return null;
  return store.keys().find((entry) => entry.normalized === normalized) || null;
}

function touch(recordFor, hwid, ip, executor) {
  recordFor.lastUsedAt = Date.now();
  recordFor.uses = (recordFor.uses || 0) + 1;
  recordFor.lastIp = ip || recordFor.lastIp || "";
  if (executor) recordFor.lastExecutor = String(executor).slice(0, 48);
  if (hwid && !recordFor.hwid) {
    recordFor.hwid = hwid;
    recordFor.firstUsedAt = Date.now();
    recordFor.hwidHistory = recordFor.hwidHistory || [];
    recordFor.hwidHistory.unshift({ at: Date.now(), hwid });
    if (recordFor.hwidHistory.length > 10) recordFor.hwidHistory.length = 10;
  }
  store.save();
}

function publicKeyView(recordFor) {
  return {
    id: recordFor.id,
    key: recordFor.key,
    plan: recordFor.plan || "",
    note: recordFor.note || "",
    createdAt: recordFor.createdAt,
    expiresAt: recordFor.expiresAt || 0,
    hwid: recordFor.hwid || "",
    lastUsedAt: recordFor.lastUsedAt || 0,
    lastIp: recordFor.lastIp || "",
    lastExecutor: recordFor.lastExecutor || "",
    uses: recordFor.uses || 0,
    revoked: !!recordFor.revoked,
    lastResetAt: recordFor.lastResetAt || 0,
    selfResets: recordFor.selfResets || 0,
  };
}

function createKeys(body) {
  const count = Math.max(1, Math.min(100, Number(body.count) || 1));
  const days = Math.max(0, Math.min(3650, Number(body.days) || 0));
  // hours is what a claimed key uses: a claim hands out a short key, not a week
  const hours = Math.max(0, Math.min(87600, Number(body.hours) || 0));
  const plan = String(body.plan || "").slice(0, 32);
  const note = String(body.note || "").slice(0, 80);
  const now = Date.now();
  const made = [];

  for (let index = 0; index < count; index++) {
    let key = license.generateKey();
    while (store.keys().some((entry) => entry.normalized === license.normalizeKey(key))) {
      key = license.generateKey();
    }
    const item = {
      id: crypto.randomUUID(),
      key,
      normalized: license.normalizeKey(key),
      plan,
      note,
      createdAt: now,
      expiresAt: hours > 0 ? now + hours * HOUR : days > 0 ? now + days * DAY : 0,
      hwid: "",
      uses: 0,
      revoked: false,
    };
    store.keys().push(item);
    made.push(publicKeyView(item));
  }

  store.save();
  record(
    "GENERATE",
    `${made.length} key${made.length === 1 ? "" : "s"}${
      hours ? `, ${hours}h` : days ? `, ${days}d` : ", lifetime"
    }`
  );
  return made;
}

// ------------------------------------------------------------------ client
function handlePing() {
  const settings = store.settings();
  return reply({
    ok: true,
    server: settings.brand || "rage.rip",
    version: VERSION,
    time: Date.now(),
    maintenance: !!settings.maintenance,
    keyless: !!settings.keyless,
  });
}

function handleConfig() {
  const settings = store.settings();
  return reply({
    ok: true,
    brand: settings.brand,
    version: VERSION,
    maintenance: !!settings.maintenance,
    maintenanceMessage: settings.maintenanceMessage,
    keyless: !!settings.keyless,
    minVersion: settings.minVersion,
    claimEnabled: !!settings.claimEnabled,
    keyUrl: scriptKeyUrl(settings),
    discordUrl: settings.discordUrl,
    downloadUrl: settings.downloadUrl,
  });
}

function bump(name) {
  store.counters()[name] = (store.counters()[name] || 0) + 1;
  store.save();
}

function rejectAuth(code, error, extra) {
  bump("rejected");
  return reply({ ok: false, code, error, ...(extra || {}) });
}

function handleAuth(request, data) {
  const settings = store.settings();
  const ip = clientIp(request);
  const hwid = String(data.hwid || "").trim().slice(0, 128);
  const executor = String(data.executor || "").trim().slice(0, 48);
  const version = String(data.version || "").trim();
  const rawKey = String(data.key || "");
  bump("auth");

  if (!limiter.hit("ip:" + ip, 20, MINUTE).allowed) {
    record("LIMIT", "auth rate limited", { ip });
    return rejectAuth("RATE_LIMITED", "too many attempts, wait a minute");
  }
  if (settings.maintenance) {
    record("REJECT", "auth refused: maintenance", { key: shortKey(rawKey), ip });
    return rejectAuth("MAINTENANCE", settings.maintenanceMessage);
  }
  if (settings.minVersion && version && compareVersions(version, settings.minVersion) < 0) {
    record("REJECT", "auth refused: outdated script", { ip });
    return rejectAuth("OUTDATED", "this version is too old, update the script");
  }
  if (!hwid || hwid.length < 8) {
    record("REJECT", "auth refused: no device id", { key: shortKey(rawKey), ip });
    return rejectAuth("NO_HWID", "could not read a device id from this executor");
  }

  const ttlMs = (Number(settings.sessionMinutes) || 90) * MINUTE;
  const ua = userAgent(request);
  const seen = { hwid: hwid.slice(0, 10), executor, ip, ua };
  const keyRecord = findKey(rawKey);
  const decision = keyRecord
    ? license.decide(keyRecord, hwid, settings)
    : { ok: false, code: "INVALID", error: "invalid key" };

  if (!decision.ok) {
    // keyless mode accepts anything at all: a wrong key, a revoked one, an
    // empty box. a key that still works keeps its own identity further down,
    // so the panel can tell a real key from a free run.
    if (!settings.keyless) {
      if (keyRecord && !limiter.hit("key:" + keyRecord.normalized, 30, MINUTE).allowed) {
        record("LIMIT", "auth rate limited", { key: shortKey(keyRecord.key), ...seen });
        return rejectAuth("RATE_LIMITED", "too many attempts, wait a minute");
      }
      record("REJECT", "auth refused: " + String(decision.code).toLowerCase().replace(/_/g, " "), {
        key: shortKey(keyRecord ? keyRecord.key : rawKey),
        ...seen,
      });
      return rejectAuth(decision.code, decision.error, {
        canSelfReset: !!decision.canSelfReset,
        resetCooldownHours: settings.resetCooldownHours,
      });
    }

    const keylessHeld = store.activeKick("keyless");
    if (keylessHeld) {
      record("REJECT", "auth refused: kicked session", { ...seen });
      return rejectAuth("KICKED", keylessHeld.reason);
    }

    const token = license.issueToken({ id: "keyless" }, hwid, store.tokenSecret(), ttlMs);
    // the row the session is tracked on, kept in hand because the same answer now
    // carries what is waiting for it
    const keylessSession = sessionFields(request, data, { sid: "keyless", hwid, keyless: true, plan: "keyless" });
    store.touchSession(keylessSession, ttlMs);
    record(
      "AUTH",
      String(rawKey).trim() ? "any key accepted - keyless mode" : "keyless session - no key given",
      { key: shortKey(rawKey), ...seen }
    );
    bump("accepted");
    return reply({
      ok: true,
      token,
      expire: ttlMs / 1000,
      keyless: true,
      plan: "keyless",
      note: "",
      hwid,
      heartbeat: store.HEARTBEAT_SECONDS,
      // the script has no timer any more, so the login answer is also the first
      // delivery of whatever is queued for this device
      ...leaseExtras(keylessSession.sid),
    });
  }

  if (!limiter.hit("key:" + keyRecord.normalized, 30, MINUTE).allowed) {
    record("LIMIT", "auth rate limited", { key: shortKey(keyRecord.key), ...seen });
    return rejectAuth("RATE_LIMITED", "too many attempts, wait a minute");
  }

  // the session id carries the device, so the kick hold is checked on the same
  // row id the heartbeat uses: a kicked device stays out, another device on the
  // same key is not touched by it
  const fields = sessionFields(request, data, {
    sid: keyRecord.id,
    keyId: keyRecord.id,
    key: shortKey(keyRecord.key),
    plan: keyRecord.plan || "",
    hwid,
  });
  const held = store.activeKick(fields.sid);
  if (held) {
    record("REJECT", "auth refused: kicked session", { key: shortKey(keyRecord.key), ...seen });
    return rejectAuth("KICKED", held.reason);
  }

  touch(keyRecord, hwid, ip, executor);
  store.touchSession(fields, ttlMs);

  const token = license.issueToken({ id: keyRecord.id }, hwid, store.tokenSecret(), ttlMs);
  record("AUTH", decision.action === "first-bind" ? "key accepted, device locked" : "key accepted", {
    key: shortKey(keyRecord.key),
    ...seen,
  });
  bump("accepted");

  return reply({
    ok: true,
    token,
    expire: ttlMs / 1000,
    plan: keyRecord.plan || "",
    note: keyRecord.note || "",
    key: keyRecord.key,
    hwid,
    firstBind: decision.action === "first-bind",
    expiresAt: keyRecord.expiresAt || 0,
    hoursLeft: license.hoursLeft(keyRecord),
    heartbeat: store.HEARTBEAT_SECONDS,
    // the script has no timer any more, so the login answer is also the first
    // delivery of whatever is queued for this device
    ...leaseExtras(fields.sid),
  });
}

function handleHeartbeat(request, data) {
  const settings = store.settings();
  const ip = clientIp(request);
  const ua = userAgent(request);
  const ttlMs = (Number(settings.sessionMinutes) || 90) * MINUTE;
  bump("heartbeats");

  const payload = license.readToken(String(data.token || ""), store.tokenSecret());
  if (!payload || payload.exp < Date.now()) {
    record("REJECT", "heartbeat refused: bad session", { ip, ua });
    return rejectAuth("BAD_SESSION", "session expired, re-enter your key");
  }
  if (settings.maintenance) {
    record("REJECT", "heartbeat refused: maintenance", { ip, ua });
    return rejectAuth("MAINTENANCE", settings.maintenanceMessage);
  }
  if (payload.kid === "keyless") {
    if (!settings.keyless) {
      record("REJECT", "heartbeat refused: keyless off", { ip, ua });
      return rejectAuth("INVALID", "keyless mode is off");
    }
    const keylessFields = sessionFields(request, data, {
      sid: "keyless",
      hwid: payload.hwid,
      keyless: true,
      plan: "keyless",
    });
    const keylessKick = store.activeKick(keylessFields.sid);
    if (keylessKick) {
      record("KICK", "session kicked: " + keylessKick.reason, { ip, ua, hwid: keylessFields.hwid });
      return reply({ ok: false, code: "KICKED", error: keylessKick.reason });
    }
    store.touchSession(keylessFields, ttlMs);
    storeLines(request, data, keylessFields.sid, payload.hwid);
    const token = license.issueToken({ id: "keyless" }, payload.hwid, store.tokenSecret(), ttlMs);
    return reply({ ok: true, token, expire: ttlMs / 1000, heartbeat: store.HEARTBEAT_SECONDS, keyless: true, ...leaseExtras(keylessFields.sid) });
  }

  const recordFor = store.keys().find((entry) => entry.id === payload.kid) || null;
  const decision = license.decide(recordFor, payload.hwid, settings);
  if (!decision.ok) {
    record("REJECT", "heartbeat refused: " + String(decision.code).toLowerCase().replace(/_/g, " "), {
      key: recordFor ? shortKey(recordFor.key) : "(deleted)",
      ip,
      ua,
    });
    return rejectAuth(decision.code, decision.error);
  }

  const fields = sessionFields(request, data, {
    sid: recordFor.id,
    keyId: recordFor.id,
    key: shortKey(recordFor.key),
    plan: recordFor.plan || "",
    hwid: payload.hwid,
  });

  // a kicked session stays refused with its reason until the hold runs out, so
  // the row cannot be recreated by the next beat that was already in flight
  const kick = store.activeKick(fields.sid);
  if (kick) {
    record("KICK", "session kicked: " + kick.reason, {
      key: shortKey(recordFor.key),
      ip,
      ua,
      hwid: fields.hwid,
    });
    return reply({ ok: false, code: "KICKED", error: kick.reason });
  }

  store.touchSession(fields, ttlMs);
  storeLines(request, data, fields.sid, payload.hwid);

  const token = license.issueToken({ id: recordFor.id }, payload.hwid, store.tokenSecret(), ttlMs);
  recordFor.lastSeenAt = Date.now();
  store.save();
  return reply({
    ok: true,
    token,
    expire: ttlMs / 1000,
    hoursLeft: license.hoursLeft(recordFor),
    heartbeat: store.HEARTBEAT_SECONDS,
    ...leaseExtras(fields.sid),
  });
}

// the script posts whatever its console printed since the last beat, and the
// answer to a command it just ran. both are session authenticated.
function handleConsole(request, data) {
  const payload = license.readToken(String(data.token || ""), store.tokenSecret());
  if (!payload || payload.exp < Date.now()) return rejectAuth("BAD_SESSION", "session expired");

  const settings = store.settings();
  const sid =
    payload.kid === "keyless"
      ? sessionFields(request, data, { sid: "keyless", hwid: payload.hwid, keyless: true }).sid
      : sessionFields(request, data, { sid: payload.kid, hwid: payload.hwid }).sid;

  return reply({
    ok: true,
    added: storeLines(request, data, sid, payload.hwid),
    heartbeat: store.HEARTBEAT_SECONDS,
  });
}

function handleCommandDone(request, data) {
  const payload = license.readToken(String(data.token || ""), store.tokenSecret());
  if (!payload || payload.exp < Date.now()) return rejectAuth("BAD_SESSION", "session expired");

  const item = store.finishCommand(String(data.id || ""), data.ok, data.result);
  if (!item) return reply({ ok: false, error: "unknown command" }, 404);

  record(
    "RUN",
    `${item.kind} ${item.ok ? "finished" : "failed"}${
      item.result ? ": " + String(item.result).slice(0, 200) : ""
    }`,
    { hwid: payload.hwid, ip: clientIp(request), ua: userAgent(request) }
  );
  return reply({ ok: true });
}

function handleUnbind(request, data) {
  const settings = store.settings();
  const ip = clientIp(request);
  const hwid = String(data.hwid || "").trim().slice(0, 128);
  const recordFor = findKey(data.key);

  if (!recordFor) return rejectAuth("INVALID", "invalid key");
  if (recordFor.revoked) return rejectAuth("REVOKED", "this key has been revoked");
  if (recordFor.expiresAt && Date.now() >= recordFor.expiresAt) {
    return rejectAuth("EXPIRED", "this key has expired");
  }
  if (!settings.allowSelfReset) {
    return rejectAuth("LOCKED", "device resets are closed, ask the owner");
  }

  const now = Date.now();
  if (!license.selfResetReady(recordFor, settings, now)) {
    record("REJECT", "hwid reset refused: cooldown", { key: shortKey(recordFor.key), ip });
    return rejectAuth("COOLDOWN", `you already reset this key, try again in ${settings.resetCooldownHours}h`);
  }

  recordFor.hwid = "";
  recordFor.lastResetAt = now;
  recordFor.selfResets = (recordFor.selfResets || 0) + 1;
  store.save();
  record("RESET", "self hwid reset", { key: shortKey(recordFor.key), ip, hwid: hwid.slice(0, 10) });
  return reply({ ok: true, message: "device lock cleared, authenticate again" });
}

// -------------------------------------------------------------- key claims
function claimCookie(id) {
  const expires = Date.now() + CLAIM_TTL_MS;
  const body = id + "." + expires;
  const sig = crypto.createHmac("sha256", store.tokenSecret()).update(body).digest("hex");
  return body + "." + sig;
}

function claimIdFromCookie(request) {
  const value = cookies(request).rr_claim;
  if (!value) return null;
  const parts = value.split(".");
  if (parts.length !== 3) return null;
  const [id, expires, sig] = parts;
  const expected = crypto.createHmac("sha256", store.tokenSecret()).update(id + "." + expires).digest("hex");
  if (!license.safeEqual(expected, sig)) return null;
  if (Number(expires) < Date.now()) return null;
  return id;
}

function pruneClaims() {
  const cutoff = Date.now() - 3 * DAY;
  const list = store.claims();
  for (let index = list.length - 1; index >= 0; index--) {
    if (list[index].createdAt < cutoff) list.splice(index, 1);
  }
  if (list.length > 500) list.length = 500;
}

// a claim holds one stage per link. step 1 is the claim itself, so a claim that
// was written before the later links existed still reads as step 1, and every
// further step lives in its own object, created the first time it is needed.
function claimStep(claim, step) {
  if (step <= 1) return claim;
  const name = "step" + step;
  if (!claim[name] || typeof claim[name] !== "object") claim[name] = {};
  return claim[name];
}

// one stage's wait runs from the moment that stage's visit came back, or from
// when its link was handed out while the return requirement is off
function stageWaitLeft(claim, stage, settings, now) {
  const from = stage.verifiedAt || stage.linkAt || claim.createdAt;
  return Math.max(
    0,
    Math.ceil((from + (Number(settings.claimWaitSeconds) || 0) * 1000 - now) / 1000)
  );
}

// a stage is finished when its visit comes back. with the return requirement off
// there is nothing to check, so the clock running out is what finishes it - and
// that still walks the visitor through both links instead of skipping the second.
function stageDone(claim, stage, settings, now) {
  if (settings.claimRequireReturn === false) return stageWaitLeft(claim, stage, settings, now) === 0;
  return !!stage.verifiedAt;
}

function claimBlocked(claim) {
  for (let step = 1; step <= CLAIM_STEPS; step++) {
    if (claimStep(claim, step).blockedAt) return true;
  }
  return false;
}

// which link the visitor is on: the first one whose visit has not come back, and
// the last one once every earlier visit has
function claimStepNow(claim, settings, now) {
  const stamp = now || Date.now();
  for (let step = 1; step <= CLAIM_STEPS; step++) {
    if (!stageDone(claim, claimStep(claim, step), settings, stamp)) return step;
  }
  return CLAIM_STEPS;
}

function claimView(claim, settings, now) {
  const stamp = now || Date.now();
  const stages = [];
  for (let step = 1; step <= CLAIM_STEPS; step++) {
    const stage = claimStep(claim, step);
    stages.push({
      stage,
      waitLeft: stageWaitLeft(claim, stage, settings, stamp),
      done: stageDone(claim, stage, settings, stamp),
    });
  }

  // the visitor stands on the first link whose visit has not come back, and on
  // the last one once every earlier visit has
  const open = stages.findIndex((entry) => !entry.done);
  const step = open < 0 ? CLAIM_STEPS : open + 1;
  const current = stages[step - 1];
  const stage = current.stage;
  const blocked = stages.find((entry) => !!entry.stage.blockedAt) || null;

  const state = claim.usedAt
    ? "redeemed"
    : blocked
      ? "blocked"
      : open < 0 && stages[CLAIM_STEPS - 1].waitLeft === 0
        ? "ready"
        : "waiting";

  return {
    ok: true,
    state,
    // the page reads this to know which link it is holding: anything after step 1
    // with no verified visit is one of the stops between them, and the last step
    // is the one that ends in the key
    step,
    steps: CLAIM_STEPS,
    url: String(stage.url || ""),
    provider: String(stage.linkProvider || ""),
    // whether this step's visit already came back. that is the difference
    // between "open the next link" and "your key is next"
    verified: !!stage.verifiedAt,
    blocked: !!blocked,
    blockedReason: String((blocked && blocked.stage.blockedReason) || ""),
    // the wait runs from when the visit came back, so it drains instead of
    // reporting the full wait forever, and it is the last step's that matters
    waitLeft: step === CLAIM_STEPS ? stages[CLAIM_STEPS - 1].waitLeft : current.waitLeft,
    requireReturn: settings.claimRequireReturn !== false,
    hours: Number(settings.claimHours) || 0,
    key: claim.key || "",
    expiresAt: claim.expiresAt || 0,
  };
}

function claimResponse(claim, settings) {
  return reply(claimView(claim, settings, Date.now()), 200, {
    "Set-Cookie": `rr_claim=${encodeURIComponent(claimCookie(claim.id))}; Path=/; HttpOnly; SameSite=Lax; Max-Age=7200`,
  });
}

// the token that travels in each link's destination: it is what proves a return
// belongs to this claim, so nobody can land on the return url and mint a key. the
// step is part of the signed body, so the first link's destination cannot be
// replayed as the second one's, or the other way round.
function claimToken(id, step) {
  return crypto
    .createHmac("sha256", store.tokenSecret())
    .update(`claim-return:${step}:${id}`)
    .digest("hex")
    .slice(0, 40);
}

function claimTokenOk(id, step, token) {
  return license.safeEqual(claimToken(id, step), String(token || ""));
}

// where this deployment lives, for the link's destination and the redirect back
function siteOrigin(request) {
  const configured = String(store.settings().publicUrl || "").trim();
  if (configured) return configured.replace(/\/+$/, "");

  const headers = request.headers || {};
  const host = String(headers.host || headers["x-forwarded-host"] || "").split(",")[0].trim();
  if (!host) return "";
  const proto = String(headers["x-forwarded-proto"] || "https").split(",")[0].trim() || "https";
  return `${proto}://${host}`;
}

function redirect(location) {
  return { status: 302, headers: { Location: location, "Cache-Control": "no-store" }, body: "" };
}

function scriptKeyUrl(settings) {
  const configured = String(settings.keyUrl || "").trim();
  if (configured) return configured;
  const origin = String(settings.publicUrl || "").trim().replace(/\/+$/, "");
  return origin ? origin + "/claim" : "";
}

// which layer builds the link: the anti-bypass one whenever its key is there, the
// plain locker otherwise, so the flow keeps working either way
function providerPick() {
  const wanted = String(store.settings().claimProvider || "bypass");
  if (wanted === "lootlabs") return { name: "lootlabs", reason: "the plain locker, chosen in the panel" };
  if (!bypass.configured()) return { name: "lootlabs", reason: "no anti-bypass key is set" };
  if (!lootlabs.configured()) return { name: "none", reason: "no lootlabs api key is set" };
  return { name: "bypass", reason: "anti-bypass on top of lootlabs" };
}

// every visit gets its own link, pointing back at this server with a token for
// this claim. that return is the proof the visit happened at all.
async function buildClaimLink(claim, request, step) {
  const settings = store.settings();
  const origin = siteOrigin(request);
  if (!origin) return { url: "", provider: "none", error: "the site url is not known yet" };

  const title = String(settings.lootTitle || settings.brand || "rage.rip").slice(0, 30);
  const back = `${origin}/api/v1/claim/return?c=${encodeURIComponent(claim.id)}&s=${step}&t=${claimToken(claim.id, step)}`;
  const pick = providerPick();

  if (pick.name === "bypass") {
    const made = await bypass.createLink({ url: back, lootKey: lootlabs.key(), settings });
    if (made.ok) {
      return { url: made.link, provider: "bypass", taskId: made.taskId, network: made.provider };
    }
    record("CLAIM", `anti-bypass link failed (${made.error}), using the plain locker instead`, {
      ip: clientIp(request),
    });
  }

  if (!lootlabs.configured()) return { url: "", provider: "none", error: pick.reason };

  const made = await lootlabs.createLink({
    url: back,
    title,
    tier: settings.lootTier,
    tasks: settings.lootTasks,
    theme: settings.lootTheme,
  });
  if (!made.ok) return { url: "", provider: "lootlabs", error: made.error };
  return { url: made.url, provider: "lootlabs", short: made.short };
}

// a stage keeps its link until the provider's 30 minute lifetime is nearly up,
// and each step is cached on its own: a later link is made only once the visitor
// is standing on it, never handed out early
async function ensureClaimLink(claim, request, step) {
  const stage = claimStep(claim, step);
  if (stage.url && Date.now() - (stage.linkAt || 0) < CLAIM_LINK_TTL_MS) return claim;

  const made = await buildClaimLink(claim, request, step);
  stage.url = made.url || "";
  stage.linkProvider = made.provider || "";
  stage.linkTaskId = made.taskId || "";
  stage.linkShort = made.short || "";
  stage.linkNetwork = made.network || "";
  stage.linkAt = Date.now();
  stage.linkError = made.url ? "" : String(made.error || "no link").slice(0, 140);
  store.save();
  if (!made.url) record("CLAIM", `no locker link for link ${step}: ` + stage.linkError, { ip: clientIp(request) });
  return claim;
}

async function handleClaimStart(request) {
  const settings = store.settings();
  const ip = clientIp(request);

  if (!settings.claimEnabled) {
    return reply({ ok: false, code: "CLOSED", error: "keys are not being handed out right now" });
  }
  if (settings.maintenance) {
    return reply({ ok: false, code: "MAINTENANCE", error: settings.maintenanceMessage });
  }
  if (!limiter.hit("claim:" + ip, 30, MINUTE).allowed) {
    return reply({ ok: false, code: "RATE_LIMITED", error: "slow down and try again in a minute" });
  }

  const now = Date.now();
  pruneClaims();

  const open = store.claims().find((claim) => claim.ip === ip && !claim.usedAt && now - claim.createdAt < CLAIM_TTL_MS);
  if (open) {
    // the page asks for the link of the step the visitor is standing on: the
    // first one, or the second one once the first visit has come back
    await ensureClaimLink(open, request, claimStepNow(open, settings, now));
    return claimResponse(open, settings);
  }

  // both limits are off unless the owner sets them: a key already costs three
  // monetized visits, so the flow itself is the limit. a stored 0 - the default -
  // means no cap, and the panel says so next to each box.
  const mine = store.claims().filter((claim) => claim.ip === ip);
  const dailyMax = Number(settings.claimMaxPerDay) || 0;
  const today = mine.filter((claim) => claim.createdAt > now - DAY).length;
  if (dailyMax > 0 && today >= dailyMax) {
    record("CLAIM", "claim refused: daily limit", { ip });
    return reply({ ok: false, code: "DAILY_LIMIT", error: `you already claimed ${today} keys today, come back tomorrow` });
  }

  const last = mine.reduce((newest, claim) => Math.max(newest, claim.createdAt), 0);
  const cooldownMs = (Number(settings.claimCooldownHours) || 0) * HOUR;
  if (cooldownMs > 0 && last && now - last < cooldownMs) {
    const hours = Math.max(1, Math.ceil((cooldownMs - (now - last)) / HOUR));
    record("CLAIM", "claim refused: cooldown", { ip });
    return reply({ ok: false, code: "COOLDOWN", error: `you got a key recently, try again in ${hours}h` });
  }

  const claim = { id: crypto.randomUUID(), createdAt: now, ip, usedAt: 0, key: "", keyId: "" };
  store.claims().unshift(claim);
  store.save();
  await ensureClaimLink(claim, request, 1);
  const stage = claimStep(claim, 1);
  record(
    "CLAIM",
    `claim started - ${stage.linkProvider || "no"} link` +
      (stage.linkNetwork ? ` (${stage.linkNetwork})` : ""),
    { ip, ua: userAgent(request) }
  );
  return claimResponse(claim, settings);
}

// the destination of a locker link: the visitor lands here with their claim
// token, and this is where the anti-bypass report decides whether the visit was
// real. every step but the last sends them on to the stop that holds the next
// link, and the last is what makes the claim redeemable.
async function handleClaimReturn(request, data) {
  const settings = store.settings();
  const ip = clientIp(request);
  const origin = siteOrigin(request);
  const back = `${origin}/claim`;
  const step = Math.max(1, Math.min(CLAIM_STEPS, Number(data.s) || 1));

  const claim = store.claims().find((entry) => entry.id === String(data.c || "")) || null;
  if (!claim || !claimTokenOk(claim.id, step, data.t)) {
    record("CLAIM", "return refused: the claim token did not verify", { ip });
    return redirect(back);
  }

  const stage = claimStep(claim, step);
  // the steps are ordered: a return on a later link that arrives before the one
  // before it cannot finish a claim that skipped a locker
  if (step > 1 && !claimStep(claim, step - 1).verifiedAt) {
    record("CLAIM", "return refused: the first link was not finished", { ip });
    return redirect(back);
  }

  // ManualDetectionZ puts this token on the final url: it is the report on how
  // the visit went, and it is only valid for 30 seconds, so check it right now
  const token = String(data.RS_EvaluationDT || data.rs_evaluationdt || "");
  const report = token && bypass.configured() ? await bypass.report(token) : null;

  if (report && report.ok && report.blocked.length) {
    stage.blockedAt = Date.now();
    stage.blockedReason = report.blocked.join(", ");
    stage.blockedIp = report.completionIp || ip;
    stage.verifyReport = report;
    store.save();
    record(
      "REJECT",
      `claim blocked by the anti-bypass check on link ${step} of ${CLAIM_STEPS}: ` + report.blocked.join(", "),
      { ip }
    );
    return redirect(back);
  }

  stage.verifiedAt = stage.verifiedAt || Date.now();
  stage.verifyIp = report && report.completionIp ? report.completionIp : ip;
  stage.verifyReport = report || stage.verifyReport || null;
  stage.verifyNote =
    report && report.ok
      ? report.watched.length
        ? "clean, recorded: " + report.watched.join(", ")
        : "clean"
      : token
        ? "the token could not be checked: " + String((report && report.error) || "").slice(0, 80)
        : "no anti-bypass token came back with the visit";
  store.save();

  record(
    "CLAIM",
    `visit ${step} of ${CLAIM_STEPS} came back through the ` +
      (stage.linkProvider === "bypass" ? "anti-bypass link" : "locker link") +
      (step < CLAIM_STEPS ? ` - link ${step + 1} is next` : " - the key is next") +
      " - " +
      stage.verifyNote,
    { ip }
  );
  // the step the visitor is on comes from the stored stages, never from the url.
  // the return therefore lands on a plain /claim, so there is no "step 2" address
  // for anyone to copy, bookmark or hand to somebody else.
  return redirect(back);
}

function handleClaimStatus(request) {
  const settings = store.settings();
  const id = claimIdFromCookie(request);
  if (!id) return reply({ ok: false, code: "NO_CLAIM", error: "no claim in this browser" });
  const claim = store.claims().find((entry) => entry.id === id);
  if (!claim) return reply({ ok: false, code: "NO_CLAIM", error: "that claim expired" });
  return reply(claimView(claim, settings, Date.now()));
}

function handleClaimRedeem(request) {
  const settings = store.settings();
  const ip = clientIp(request);

  if (!settings.claimEnabled) {
    return reply({ ok: false, code: "CLOSED", error: "keys are not being handed out right now" });
  }
  if (!limiter.hit("redeem:" + ip, 20, MINUTE).allowed) {
    return reply({ ok: false, code: "RATE_LIMITED", error: "slow down and try again in a minute" });
  }

  const id = claimIdFromCookie(request);
  if (!id) return reply({ ok: false, code: "NO_CLAIM", error: "start again from the get a key button" });
  const claim = store.claims().find((entry) => entry.id === id);
  if (!claim) return reply({ ok: false, code: "NO_CLAIM", error: "that claim expired, start again" });

  if (claim.usedAt) {
    return reply({ ...claimView(claim, settings, Date.now()), already: true });
  }
  if (settings.maintenance) {
    return reply({ ok: false, code: "MAINTENANCE", error: settings.maintenanceMessage });
  }
  if (claimBlocked(claim)) {
    record("CLAIM", "claim refused: blocked by the anti-bypass check", { ip });
    return reply({ ok: false, code: "BLOCKED", error: "this visit was flagged by the anti-bypass check" });
  }

  // every link has to be finished: handing the key out early would throw away
  // the visits the flow was built to earn
  const stamp = Date.now();
  let pending = 0;
  for (let step = 1; step <= CLAIM_STEPS; step++) {
    if (!stageDone(claim, claimStep(claim, step), settings, stamp)) {
      pending = step;
      break;
    }
  }
  if (pending) {
    record("CLAIM", `claim refused: link ${pending} of ${CLAIM_STEPS} was not finished`, { ip });
    return reply({
      ok: false,
      code: "NOT_VERIFIED",
      step: pending,
      error: "finish the links first - the key is handed out once every visit comes back through them",
    });
  }

  const view = claimView(claim, settings, stamp);
  if (view.waitLeft > 0) {
    return reply({ ok: false, code: "WAIT", error: `${view.waitLeft}s to go`, waitLeft: view.waitLeft });
  }

  const made = createKeys({ count: 1, hours: settings.claimHours, note: "claimed by " + ip });
  const created = made[0];

  claim.usedAt = Date.now();
  claim.key = created.key;
  claim.keyId = created.id;
  claim.expiresAt = created.expiresAt;
  store.save();
  record("CLAIM", "key handed out", { key: shortKey(created.key), ip });

  return reply({
    ok: true,
    already: false,
    state: "redeemed",
    key: created.key,
    expiresAt: created.expiresAt,
    hours: Number(settings.claimHours) || 0,
  });
}

// ------------------------------------------------------------------- panel
function adminToken() {
  const expires = Date.now() + 12 * HOUR;
  const body = String(expires);
  const sig = crypto.createHmac("sha256", store.tokenSecret()).update(body).digest("hex");
  return body + "." + sig;
}

function adminAuthed(request) {
  const value = cookies(request).rr_admin;
  if (!value) return false;
  const index = value.indexOf(".");
  if (index < 0) return false;
  const body = value.slice(0, index);
  const sig = value.slice(index + 1);
  const expected = crypto.createHmac("sha256", store.tokenSecret()).update(body).digest("hex");
  if (!license.safeEqual(expected, sig)) return false;
  const expires = Number(body);
  return Number.isFinite(expires) && expires > Date.now();
}

function sessionView(item) {
  return {
    sid: item.sid,
    key: item.key || "",
    plan: item.plan || "",
    keyless: !!item.keyless,
    hwid: item.hwid || "",
    ip: item.ip || "",
    executor: item.executor || "",
    version: item.version || "",
    place: item.place || "",
    job: item.job || "",
    ua: item.ua || "",
    // the client's own frame rate, as it reported it on its last beat, and what
    // its lua state was holding at the time
    fps: item.fps || 0,
    mem: item.mem || 0,
    inst: item.inst || 0,
    // what is waiting for this device, so the panel can say so before you open it
    pending: store.commands().filter((entry) => !entry.doneAt && (entry.sid === item.sid || entry.sid === "*")).length,
    startedAt: item.startedAt || 0,
    lastSeenAt: item.lastSeenAt || 0,
    expiresAt: item.expiresAt || 0,
    beats: item.beats || 0,
    // with no beat this is the only thing the panel can honestly say about
    // presence: this row spoke to us recently
    live: Date.now() - (item.lastSeenAt || 0) < store.SESSION_LIVE_MS,
    // a kicked row is kept until its beats stop, so the panel can say the kick
    // landed instead of the person simply disappearing from the list
    kicked: !!item.kickedAt,
    kickedAt: item.kickedAt || 0,
    kickReason: item.kickReason || "",
  };
}

function overview() {
  const settings = store.settings();
  const keys = store.keys().map(publicKeyView);
  const now = Date.now();
  const active = keys.filter((key) => !key.revoked && (!key.expiresAt || key.expiresAt > now));
  const today = store.claims().filter((claim) => claim.createdAt > now - DAY).length;
  // every row whose session token has not expired. without a beat there is no way
  // to know whether somebody is still in the game, so a row is listed on the
  // strength of its token and stamped with when it last spoke; the panel calls it
  // live only for the ones that spoke recently
  const sessions = store
    .sessions()
    .filter((item) => (item.expiresAt || 0) > now)
    .map(sessionView)
    .sort((left, right) => right.lastSeenAt - left.lastSeenAt);

  return {
    ok: true,
    version: VERSION,
    server: {
      port: "",
      bind: "netlify",
      lan: [],
      publicUrl: settings.publicUrl || "",
      uptimeSeconds: 0,
      usingEnvPassword: !!process.env.ADMIN_PASSWORD,
      storage: process.env.LOCAL_STATE_FILE ? "local file (dev)" : "netlify blobs",
      keyless: !!settings.keyless,
      maintenance: !!settings.maintenance,
    },
    stats: {
      ...store.counters(),
      claims: store.claims().filter((claim) => claim.usedAt).length,
      claimsToday: today,
      totalKeys: keys.length,
      activeKeys: active.length,
      bound: keys.filter((key) => key.hwid && !key.revoked).length,
      revoked: keys.filter((key) => key.revoked).length,
      expired: keys.filter((key) => key.expiresAt && key.expiresAt <= now).length,
      sessions: sessions.length,
      requests: store.requests().length,
    },
    webhook: {
      url: settings.webhookUrl || "",
      host: webhook.hostOf(settings.webhookUrl || ""),
      discord: webhook.isDiscord(settings.webhookUrl || ""),
    },
    claim: {
      enabled: !!settings.claimEnabled,
      provider: providerPick().name,
      providerReason: providerPick().reason,
      bypassKey: bypass.configured(),
      lootKey: lootlabs.configured(),
      postback: bypass.postbackUrl(lootlabs.key()),
      keyUrl: scriptKeyUrl(settings),
    },
    settings,
    keys: keys.sort((a, b) => b.createdAt - a.createdAt),
    sessions,
    events: store.recentEvents(80),
    requests: store.requests().slice(0, 120),
  };
}

// everything the three dot menu on a session row can do. one route, one switch,
// so the panel never needs a second round of endpoints.
function sessionAction(body) {
  const sid = String(body.sid || "");
  const action = String(body.action || "");
  const session = store.sessions().find((entry) => entry.sid === sid) || null;
  const keyRecord = session && session.keyId ? store.keys().find((entry) => entry.id === session.keyId) : null;
  // a row is only listed while its beats keep arriving, so a missing one means
  // the client is gone: queueing there would look sent and never run
  if (!session) {
    return { ok: false, error: "that session is gone - it stopped checking in" };
  }
  const tag = { hwid: session ? session.hwid : "", key: keyRecord ? shortKey(keyRecord.key) : "" };

  switch (action) {
    case "lua": {
      const source = String(body.source || "").slice(0, 20000);
      if (!source.trim()) return { ok: false, error: "the lua box is empty" };
      const command = store.queueCommand({ sid, kind: "lua", body: source });
      record("EXEC", `lua queued (${source.length} bytes)`, tag);
      return { ok: true, id: command.id, queued: true };
    }
    case "notify": {
      const message = String(body.message || "").trim().slice(0, 500);
      if (!message) return { ok: false, error: "type a message first" };
      const command = store.queueCommand({ sid, kind: "notify", body: message });
      record("NOTIFY", "message queued: " + message, tag);
      return { ok: true, id: command.id, queued: true };
    }
    case "kick": {
      const reason = String(body.reason || "").trim().slice(0, 200) || "removed by the owner";
      const dropped = store.kickSession(sid, reason);
      record("KICK", "session kicked: " + reason, tag);
      return { ok: true, kicked: !!dropped };
    }
    case "reveal": {
      return {
        ok: true,
        key: keyRecord ? keyRecord.key : "",
        hwid: session ? session.hwid : "",
        ip: session ? session.ip : "",
        note: keyRecord ? keyRecord.note || "" : "",
        plan: keyRecord ? keyRecord.plan || "" : "",
        job: session ? session.job || "" : "",
        place: session ? session.place || "" : "",
      };
    }
    case "console": {
      return {
        ok: true,
        lines: store.linesFor(sid).slice(-200),
        commands: store
          .commands()
          .filter((entry) => entry.sid === sid || entry.sid === "*")
          .slice(0, 20),
      };
    }
    case "clear-console": {
      return { ok: true, cleared: store.clearLines(sid) };
    }
    default:
      return { ok: false, error: "unknown session action" };
  }
}

function updateKey(body) {
  const list = store.keys();
  const index = list.findIndex((entry) => entry.id === body.id);
  if (index < 0) return { ok: false, error: "key not found" };
  const item = list[index];
  const action = String(body.action || "");

  switch (action) {
    case "revoke":
      item.revoked = true;
      record("ADMIN", "key revoked", { key: shortKey(item.key) });
      break;
    case "restore":
      item.revoked = false;
      record("ADMIN", "key restored", { key: shortKey(item.key) });
      break;
    case "delete":
      list.splice(index, 1);
      record("ADMIN", "key deleted", { key: shortKey(item.key) });
      break;
    case "reset-hwid":
      item.hwid = "";
      item.lastResetAt = Date.now();
      record("ADMIN", "device lock reset by owner", { key: shortKey(item.key) });
      break;
    case "extend": {
      // hours, because a claimed key lives for hours now: the panel offers 1h to
      // 90d and anything it does not offer can be typed in
      const hours = Number(body.hours) || 0;
      if (!Number.isFinite(hours) || hours <= 0) return { ok: false, error: "pick how long to add" };
      // ten years is the ceiling, and the cap belongs on the hours, not on the
      // milliseconds: capping the product turned every extension into seconds
      const add = Math.round(Math.min(24 * 3650, hours) * HOUR);
      const base = Math.max(Date.now(), item.expiresAt || 0);
      item.expiresAt = base + add;
      record("ADMIN", `key extended by ${roundHours(hours)}`, { key: shortKey(item.key) });
      break;
    }
    case "shorten": {
      const hours = Number(body.hours) || 0;
      if (!Number.isFinite(hours) || hours <= 0) return { ok: false, error: "pick how long to remove" };
      const cut = Math.round(Math.min(24 * 3650, hours) * HOUR);
      const left = (item.expiresAt || 0) - cut;
      item.expiresAt = Math.max(0, left);
      record("ADMIN", `key shortened by ${roundHours(hours)}`, { key: shortKey(item.key) });
      break;
    }
    case "set-note":
      item.note = String(body.note || "").slice(0, 80);
      break;
    case "set-plan":
      item.plan = String(body.plan || "").slice(0, 32);
      break;
    default:
      return { ok: false, error: "unknown action" };
  }

  store.save();
  return { ok: true, key: publicKeyView(item) };
}

const SETTING_TYPES = {
  brand: "string",
  publicUrl: "string",
  keyUrl: "string",
  discordUrl: "string",
  downloadUrl: "string",
  maintenanceMessage: "string",
  minVersion: "string",
  claimProvider: "string",
  lootTitle: "string",
  webhookUrl: "url",
  keyless: "bool",
  logRequests: "bool",
  maintenance: "bool",
  hwidLock: "bool",
  allowSelfReset: "bool",
  sealedOnly: "bool",
  claimEnabled: "bool",
  claimRequireReturn: "bool",
  bypassVm: "bool",
  resetCooldownHours: "number",
  sessionMinutes: "number",
  claimWaitSeconds: "number",
  claimCooldownHours: "number",
  claimMaxPerDay: "number",
  claimHours: "number",
  lootTier: "number",
  lootTasks: "number",
  lootTheme: "number",
  claimMinSeconds: "number",
};

function updateSettings(body) {
  const settings = store.settings();
  const changed = [];
  for (const [name, type] of Object.entries(SETTING_TYPES)) {
    if (!(name in body)) continue;
    const raw = body[name];
    if (type === "bool") {
      settings[name] = raw === true || raw === "true" || raw === 1 || raw === "1";
    } else if (type === "number") {
      const value = Number(raw);
      if (!Number.isFinite(value)) continue;
      settings[name] = Math.max(0, Math.min(100000, Math.floor(value)));
      if (name === "sessionMinutes") settings[name] = Math.max(1, Math.min(1440, settings[name]));
    } else if (type === "url") {
      // an empty box clears it, anything that is not an http(s) address is
      // ignored rather than stored as a broken endpoint
      const value = String(raw || "").trim().slice(0, 400);
      if (value && !webhook.validUrl(value)) continue;
      settings[name] = value;
    } else {
      settings[name] = String(raw || "").slice(0, 200).trim();
    }
    changed.push(name);
  }
  store.save();
  if (changed.length) record("ADMIN", "settings updated: " + changed.join(", "));
  return { ok: true, settings };
}

function hwidTest(body) {
  const settings = store.settings();
  const hwid = String(body.hwid || "").trim();
  const recordFor = findKey(body.key);
  if (!recordFor) {
    return { ok: true, decision: { ok: false, code: "INVALID", error: "invalid key" }, note: "nothing stored under that key" };
  }
  const decision = license.decide(recordFor, hwid, settings);
  return {
    ok: true,
    decision,
    key: publicKeyView(recordFor),
    wouldBind: !recordFor.hwid && decision.ok,
  };
}

async function handleAdmin(request, route, body) {
  const authed = adminAuthed(request);

  if (route === "login" && request.method === "POST") {
    const password = store.password();
    if (!password) {
      return reply({ ok: false, error: "ADMIN_PASSWORD is not set in this site's environment" }, 500);
    }
    if (!license.safeEqual(String(body.password || ""), password)) {
      record("ADMIN", "panel login failed", { ip: clientIp(request) });
      return reply({ ok: false, error: "wrong password" }, 401);
    }
    record("ADMIN", "panel login", { ip: clientIp(request) });
    return reply({ ok: true }, 200, {
      "Set-Cookie": `rr_admin=${encodeURIComponent(adminToken())}; Path=/; HttpOnly; SameSite=Lax; Max-Age=43200`,
    });
  }

  if (route === "logout" && request.method === "POST") {
    return reply({ ok: true }, 200, { "Set-Cookie": "rr_admin=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0" });
  }

  if (route === "session") return reply({ ok: true, authed });

  if (!authed) return reply({ ok: false, error: "not signed in" }, 401);

  switch (route) {
    case "overview":
      return reply(overview());
    case "keys/generate":
      return reply({ ok: true, keys: createKeys(body) });
    case "keys/update":
      return reply(updateKey(body));
    case "settings":
      return reply(updateSettings(body));
    case "hwid-test":
      return reply(hwidTest(body));
    case "webhook/test": {
      const url = store.settings().webhookUrl;
      if (!url) return reply({ ok: false, error: "no webhook url is set" }, 400);
      const result = await webhook.deliver(
        url,
        {
          type: "TEST",
          message: "test event from the panel",
          ip: clientIp(request),
          ua: userAgent(request),
        },
        { brand: store.settings().brand }
      );
      record(
        "WEBHOOK",
        result.ok
          ? `test event delivered to ${result.host} (${result.status}, ${result.ms}ms)`
          : `test delivery to ${result.host || "webhook"} failed - ${result.error}`
      );
      return reply({ ok: result.ok, result, error: result.ok ? "" : result.error });
    }
    case "sessions/action": {
      return reply(sessionAction(body));
    }
    case "sessions/broadcast": {
      const message = String(body.message || "").trim().slice(0, 500);
      if (!message) return reply({ ok: false, error: "type a message first" }, 400);
      const command = store.queueCommand({ sid: "*", kind: "notify", body: message });
      record("BROADCAST", "broadcast: " + message);
      return reply({ ok: true, id: command.id, sessions: store.sessions().length });
    }
    case "activity/clear": {
      const cleared = store.clearActivity();
      record("ADMIN", `activity cleared (${cleared.events} events, ${cleared.requests} requests)`);
      return reply({ ok: true, ...cleared });
    }
    case "sessions/clear": {
      const cleared = store.clearSessions();
      record("ADMIN", `session history cleared (${cleared})`);
      return reply({ ok: true, cleared });
    }
    case "claims/clear": {
      // owner escape hatch: wipes the per-ip claim history, so the cooldown and
      // daily cap start from zero again (and a test claim does not lock you out)
      const cleared = store.claims().length;
      store.claims().length = 0;
      store.save();
      record("ADMIN", `claim history cleared (${cleared})`);
      return reply({ ok: true, cleared });
    }
    case "password": {
      if (!license.safeEqual(String(body.current || ""), store.password())) {
        return reply({ ok: false, error: "current password is wrong" }, 400);
      }
      return reply(
        { ok: false, error: "change ADMIN_PASSWORD in the site environment on Netlify, then redeploy" },
        400
      );
    }
    default:
      return reply({ ok: false, error: "unknown panel route" }, 404);
  }
}

// ------------------------------------------------------------------ dispatch
// routes that never write to the store: no lease needed for these
const READ_ONLY_ROUTES = new Set(["v1/ping", "v1/config", "admin/session", "admin/overview", "admin/hwid-test"]);

function readOnlyRoute(request) {
  if (READ_ONLY_ROUTES.has(request.route)) return true;
  return request.route === "v1/claim" && request.method !== "POST";
}

// opens the envelope on a script route, or refuses the request. the reply for a
// refusal is plain on purpose: it is the one answer meant for an old script copy
function openSealed(request, data) {
  const settings = store.settings();
  const envelope = seal.findEnvelope(data);

  if (!envelope) {
    if (!settings.sealedOnly) return { ok: true, data };
    record("REJECT", "unsealed request refused: " + request.route, {
      ip: clientIp(request),
      ua: userAgent(request),
    });
    return {
      ok: false,
      response: reply(
        {
          ok: false,
          code: "OUTDATED",
          error: "this script is out of date - get the current one",
        },
        400
      ),
    };
  }

  // a browser cannot make a sealed request, so an origin here is someone poking
  // at the api from a page
  if (settings.sealedOnly && String(request.headers.origin || "")) {
    record("REJECT", "browser request refused: " + request.route, {
      ip: clientIp(request),
      ua: userAgent(request),
    });
    return { ok: false, response: reply({ ok: false, error: "not allowed" }, 403) };
  }

  const opened = seal.open(envelope);
  if (!opened.ok) {
    record("REJECT", "sealed request refused: " + opened.code.toLowerCase(), {
      ip: clientIp(request),
      ua: userAgent(request),
    });
    return { ok: false, response: reply({ ok: false, code: opened.code, error: opened.error }, 400) };
  }

  // one nonce, once: a captured request replayed later lands here
  if (!store.useNonce(opened.nonce)) {
    record("REJECT", "replayed request refused: " + request.route, {
      ip: clientIp(request),
      ua: userAgent(request),
    });
    return {
      ok: false,
      response: reply({ ok: false, code: "REPLAY", error: "that request was already used" }, 400),
    };
  }

  request.sealed = true;
  return { ok: true, data: opened.data };
}

async function dispatch(request, data) {
  if (request.route.startsWith("admin/")) {
    return handleAdmin(request, request.route.slice("admin/".length), data);
  }

  switch (request.route) {
    case "v1/ping":
      return handlePing();
    case "v1/config":
      return handleConfig();
    case "v1/auth":
      return handleAuth(request, data);
    case "v1/heartbeat":
      return handleHeartbeat(request, data);
    case "v1/console":
      return handleConsole(request, data);
    case "v1/command/done":
      return handleCommandDone(request, data);
    case "v1/unbind":
      return handleUnbind(request, data);
    case "v1/claim":
      return request.method === "POST" ? handleClaimStart(request) : handleClaimStatus(request);
    case "v1/claim/start":
      return handleClaimStart(request);
    case "v1/claim/return":
      return handleClaimReturn(request, data);
    case "v1/claim/redeem":
      return handleClaimRedeem(request);
    
    case "cloud-config/save":
      if (request.method !== "POST") return reply({ ok: false, error: "POST required" }, 405);
      return reply(await cloudConfig.save(data.userId, data.configName, data.configData));
    
    case "cloud-config/load":
      if (request.method !== "GET") return reply({ ok: false, error: "GET required" }, 405);
      return reply(await cloudConfig.load(data.userId, data.configName));
    
    case "cloud-config/list":
      if (request.method !== "GET") return reply({ ok: false, error: "GET required" }, 405);
      return reply(await cloudConfig.list(data.userId));
    
    case "cloud-config/delete":
      if (request.method !== "POST") return reply({ ok: false, error: "POST required" }, 405);
      return reply(await cloudConfig.delete(data.userId, data.configName));
    
    default:
      return reply({ ok: false, error: "not found" }, 404);
  }
}

async function handle(request) {
  if (request.method === "OPTIONS") {
    return {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      },
      body: "",
    };
  }

  if (request.route === "healthz") return reply({ ok: true, version: VERSION });

  // a flood on the script routes is cheap to blunt here. the limits that must
  // hold (claim cooldown, daily cap, device locks) live in the stored document
  if (request.route.startsWith("v1/")) {
    const ip = clientIp(request);
    if (!limiter.hit("all:" + ip, 240, MINUTE).allowed) {
      return reply({ ok: false, code: "RATE_LIMITED", error: "too many requests from this address" }, 429);
    }
  }

  pendingWebhooks = [];
  caller = { ip: clientIp(request), ua: userAgent(request) };
  const startedAt = Date.now();
  const readOnly = readOnlyRoute(request);
  let data = {};
  let response = null;

  try {
    await store.begin(request.event, { readOnly });
  } catch (error) {
    console.error("[store]", error);
    // keep a busy lease separate from a real storage failure: they need
    // different answers, and conflating them hides configuration problems
    if (error && error.code === "BUSY") {
      return reply({ ok: false, code: "BUSY", error: "the license store is busy, try again" }, 503);
    }
    return reply({ ok: false, code: "STORAGE", error: "the license store could not be read" }, 500);
  }

  try {
    const body = parseBody(request.body);
    data = { ...(request.query || {}), ...body };

    // a refusal is a response like any other: returning from here instead would
    // leave the store's lease held, and the next request would find it busy
    if (SEALED_ROUTES.has(request.route)) {
      const opened = openSealed(request, data);
      if (!opened.ok) {
        response = opened.response;
      } else {
        data = opened.data;
      }
    }

    if (!response) response = await dispatch(request, data);
    if (request.sealed && response && typeof response.body === "string" && response.body) {
      // answer in the shape the request arrived in, so the payload of a
      // heartbeat is as unreadable to a spy as the request that caused it
      try {
        const parsed = JSON.parse(response.body);
        response.body = JSON.stringify(seal.seal(parsed));
      } catch {
        /* a body that is not json stays as it is */
      }
    }
  } catch (error) {
    console.error("[api]", error);
    response = reply({ ok: false, error: "server error" }, 500);
  }

  try {
    if (!readOnly) logRequest(request, data, response, startedAt);
  } catch (error) {
    console.error("[log]", error);
  }

  try {
    await store.commit();
  } catch (error) {
    console.error("[store] commit failed", error);
    await store.abort();
  }

  // the webhook goes out AFTER the document has been written and the lease given
  // back. it used to run before the commit, which put a slow endpoint - a discord
  // webhook being rate limited, say - inside the single lock the whole api shares:
  // every other session's beat waited that lease out and was told the store was
  // busy, and the panel went blank behind them.
  try {
    await flushWebhooks();
  } catch (error) {
    console.error("[webhook]", error);
  }

  return response;
}

module.exports = { handle, VERSION };
