/**
 * Cloudflare Worker — SimpleLogin-compatible Alias API
 *
 * Replicates the subset of the SimpleLogin API that password managers
 * (e.g. Bitwarden) use to create / manage email aliases.  Aliases are stored
 * in a KV namespace that is shared with the companion email-forwarder worker.
 *
 * Implemented endpoints (https://github.com/simple-login/app/blob/master/docs/api.md)
 * ─────────────────────
 *   GET    /api/user_info
 *   GET    /api/v5/alias/options
 *   POST   /api/v3/alias/custom/new
 *   POST   /api/alias/random/new
 *   GET    /api/v2/aliases
 *   GET    /api/aliases/:id
 *   DELETE /api/aliases/:id
 *   POST   /api/aliases/:id/toggle
 *   PATCH  /api/aliases/:id
 *   GET    /api/v2/mailboxes
 *   GET    /api/v2/setting/domains
 *   GET    /api/setting
 *   POST   /api/sync             ← import aliases from real SimpleLogin
 *
 * Environment variables (set in the Cloudflare dashboard)
 * ─────────────────────────────────────────────────────────────────────────────
 *   API_KEY        (secret) – token clients send in the Authentication header
 *   SIGNING_SECRET (secret) – random string used to HMAC-sign alias suffixes
 *   DOMAIN         – domain used for alias addresses, e.g. "mail.example.com"
 *   USER_NAME      – display name returned by /api/user_info
 *   USER_EMAIL     – real email address returned by /api/user_info
 *   MAILBOX_ID     – integer ID for the single virtual mailbox
 *   SL_BASE_URL    – (optional) SimpleLogin base URL for sync;
 *                    defaults to "https://app.simplelogin.io"
 *
 * KV schema (ALLOWED_ALIASES namespace)
 * ──────────────────────────────────────
 *   key : lowercase alias email address   e.g. "foo.bar@mail.example.com"
 *   value : JSON-encoded AliasRecord
 *
 *   Special key "__next_id__" holds the next numeric alias ID as a string.
 *
 * Compatibility with cloudflare-email-forwarder-worker
 * ─────────────────────────────────────────────────────
 *   The email worker parses the JSON value and gates on `record.enabled`, so
 *   aliases toggled here (or imported via sync) are respected immediately.
 */

// ─── Types ───────────────────────────────────────────────────────────────────

export interface Env {
  ALLOWED_ALIASES: KVNamespace;
  API_KEY: string;
  SIGNING_SECRET: string;
  DOMAIN: string;
  USER_NAME: string;
  USER_EMAIL: string;
  MAILBOX_ID?: string;
  /** Optional — defaults to https://app.simplelogin.io */
  SL_BASE_URL?: string;
}

/** Shape of a single alias object returned by the real SimpleLogin API. */
interface SLApiAlias {
  id: number;
  email: string;
  name: string | null;
  note: string | null;
  enabled: boolean;
  creation_timestamp: number;
  nb_forward: number;
  nb_block: number;
  nb_reply: number;
  pinned: boolean;
}

interface AliasRecord {
  id: number;
  email: string;
  name: string | null;
  note: string | null;
  enabled: boolean;
  creation_timestamp: number;
  nb_forward: number;
  nb_block: number;
  nb_reply: number;
  pinned: boolean;
}

// ─── Constants ────────────────────────────────────────────────────────────────

/** Small wordlist for random alias generation (word mode). */
const WORD_LIST = [
  "autumn","beach","birch","bloom","breeze","brook","cedar","cloud","coral",
  "creek","dawn","delta","dune","ember","falcon","fern","field","fjord","flame",
  "flash","flora","forest","frost","glade","glen","harbor","haven","hawk",
  "hazel","heron","hill","hollow","jade","jasper","lake","lark","linden","loch",
  "lotus","luna","maple","marsh","meadow","mist","moon","moss","moth","nova",
  "oak","opal","otter","peak","pine","pond","prism","quartz","rain","reed",
  "ridge","river","robin","rose","sage","shore","sierra","sky","slate","snow",
  "solar","sparrow","spring","spruce","star","stone","storm","stream","summit",
  "sunset","swift","terra","thistle","thorn","thunder","tide","timber","vale",
  "valley","violet","vista","wave","willow","wind","winter","wren","zenith",
];

const NEXT_ID_KEY = "__next_id__";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function err(message: string, status = 400): Response {
  return json({ error: message }, status);
}

/** Return a cryptographically random integer in [0, max). */
function randomInt(max: number): number {
  const buf = new Uint32Array(1);
  crypto.getRandomValues(buf);
  return buf[0] % max;
}

function randomWord(): string {
  return WORD_LIST[randomInt(WORD_LIST.length)];
}

function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return Array.from(buf)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ─── HMAC signing for alias suffixes ─────────────────────────────────────────

async function importHmacKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  return crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

async function signSuffix(suffix: string, secret: string): Promise<string> {
  const key = await importHmacKey(secret);
  const enc = new TextEncoder();
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(suffix));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  // Format: "<suffix>.<b64sig>" — mirrors SL's convention loosely
  return `${suffix}.${b64}`;
}

async function verifySuffix(
  signedSuffix: string,
  secret: string,
): Promise<string | null> {
  // Split at last dot that separates the suffix from its signature
  const lastDot = signedSuffix.lastIndexOf(".");
  if (lastDot === -1) return null;
  const suffix = signedSuffix.slice(0, lastDot);
  const sigB64 = signedSuffix.slice(lastDot + 1);

  try {
    // Recover the original signature bytes
    const sigBytes = Uint8Array.from(
      atob(sigB64.replace(/-/g, "+").replace(/_/g, "/")),
      (c) => c.charCodeAt(0),
    );
    const key = await importHmacKey(secret);
    const enc = new TextEncoder();
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes,
      enc.encode(suffix),
    );
    return valid ? suffix : null;
  } catch {
    return null;
  }
}

// ─── KV helpers ──────────────────────────────────────────────────────────────

async function nextId(kv: KVNamespace): Promise<number> {
  const raw = await kv.get(NEXT_ID_KEY);
  const id = raw ? parseInt(raw, 10) : 1;
  await kv.put(NEXT_ID_KEY, String(id + 1));
  return id;
}

async function getAliasById(
  kv: KVNamespace,
  id: number,
): Promise<AliasRecord | null> {
  // We must scan all keys to find a specific numeric ID.
  // For typical personal-use scale this is fine (< a few hundred aliases).
  const list = await kv.list();
  for (const key of list.keys) {
    if (key.name === NEXT_ID_KEY) continue;
    const raw = await kv.get(key.name);
    if (!raw) continue;
    try {
      const record: AliasRecord = JSON.parse(raw);
      if (record.id === id) return record;
    } catch {
      // skip malformed values
    }
  }
  return null;
}

async function getAllAliases(kv: KVNamespace): Promise<AliasRecord[]> {
  const aliases: AliasRecord[] = [];
  let cursor: string | undefined;
  do {
    const opts = cursor ? { cursor } : undefined;
    const result = await kv.list(opts);
    for (const key of result.keys) {
      if (key.name === NEXT_ID_KEY) continue;
      const raw = await kv.get(key.name);
      if (!raw) continue;
      try {
        aliases.push(JSON.parse(raw) as AliasRecord);
      } catch {
        // skip malformed values
      }
    }
    cursor = result.list_complete ? undefined : result.cursor;
  } while (cursor);

  aliases.sort((a, b) => b.creation_timestamp - a.creation_timestamp);
  return aliases;
}

function aliasToSLFormat(record: AliasRecord, mailboxId: number, mailboxEmail: string) {
  const date = new Date(record.creation_timestamp * 1000);
  const creation_date = date.toISOString().replace("T", " ").slice(0, 22) + "+00:00";
  return {
    id: record.id,
    email: record.email,
    name: record.name,
    enabled: record.enabled,
    creation_date,
    creation_timestamp: record.creation_timestamp,
    note: record.note,
    nb_block: record.nb_block,
    nb_forward: record.nb_forward,
    nb_reply: record.nb_reply,
    support_pgp: false,
    disable_pgp: false,
    pinned: record.pinned,
    mailbox: { id: mailboxId, email: mailboxEmail },
    mailboxes: [{ id: mailboxId, email: mailboxEmail }],
    latest_activity: null,
  };
}

// ─── SimpleLogin sync ────────────────────────────────────────────────────────

/**
 * Fetch every alias page from the real SimpleLogin API and upsert each one
 * into the KV store.  Matching is done by email address (the KV key).
 *
 * - Existing KV records keep their local numeric ID and have their metadata
 *   refreshed (enabled, name, note, pinned, counters).
 * - New aliases are assigned a fresh local ID via nextId().
 *
 * Returns a summary object.
 */
async function syncWithSimpleLogin(
  slApiKey: string,
  slBaseUrl: string,
  kv: KVNamespace,
): Promise<{ added: number; updated: number; total_sl: number; total_kv_after: number }> {
  // ── 1. Load existing KV aliases into a map keyed by email ────────────────
  const existing = await getAllAliases(kv);
  const kvMap = new Map<string, AliasRecord>(existing.map((a) => [a.email, a]));

  // ── 2. Page through SL's /api/v2/aliases ─────────────────────────────────
  const slAliases: SLApiAlias[] = [];
  let pageId = 0;
  while (true) {
    const resp = await fetch(
      `${slBaseUrl}/api/v2/aliases?page_id=${pageId}`,
      { headers: { Authentication: slApiKey } },
    );
    if (!resp.ok) {
      const text = await resp.text();
      throw new Error(`SL API returned ${resp.status}: ${text}`);
    }
    const data = (await resp.json()) as { aliases: SLApiAlias[] };
    if (!data.aliases || data.aliases.length === 0) break;
    slAliases.push(...data.aliases);
    pageId++;
  }

  // ── 3. Upsert each SL alias into KV ──────────────────────────────────────
  let added = 0;
  let updated = 0;

  for (const slAlias of slAliases) {
    const email = slAlias.email.toLowerCase().trim();
    const existing = kvMap.get(email);

    if (existing) {
      // Update mutable fields; preserve local ID and creation_timestamp.
      const updated_record: AliasRecord = {
        ...existing,
        name: slAlias.name,
        note: slAlias.note,
        enabled: slAlias.enabled,
        pinned: slAlias.pinned,
        nb_forward: slAlias.nb_forward,
        nb_block: slAlias.nb_block,
        nb_reply: slAlias.nb_reply,
      };
      await kv.put(email, JSON.stringify(updated_record));
      updated++;
    } else {
      // New alias — assign a local ID.
      const id = await nextId(kv);
      const record: AliasRecord = {
        id,
        email,
        name: slAlias.name,
        note: slAlias.note,
        enabled: slAlias.enabled,
        creation_timestamp: slAlias.creation_timestamp,
        nb_forward: slAlias.nb_forward,
        nb_block: slAlias.nb_block,
        nb_reply: slAlias.nb_reply,
        pinned: slAlias.pinned,
      };
      await kv.put(email, JSON.stringify(record));
      kvMap.set(email, record);
      added++;
    }
  }

  return {
    added,
    updated,
    total_sl: slAliases.length,
    total_kv_after: kvMap.size,
  };
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

function authenticate(request: Request, env: Env): boolean {
  const header = request.headers.get("Authentication") ?? "";
  return header === env.API_KEY;
}

// ─── Router ───────────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    // CORS pre-flight
    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Authentication, Content-Type",
        },
      });
    }

    // All API routes require authentication except none (SL has no public endpoints)
    if (!authenticate(request, env)) {
      return err("Invalid API key", 401);
    }

    const mailboxId = parseInt(env.MAILBOX_ID ?? "1", 10) || 1;

    // ── GET /api/user_info ────────────────────────────────────────────────────
    if (method === "GET" && path === "/api/user_info") {
      return json({
        name: env.USER_NAME,
        email: env.USER_EMAIL,
        is_premium: true,
        in_trial: false,
        profile_picture_url: null,
        max_alias_free_plan: 999999,
      });
    }

    // ── GET /api/v5/alias/options ─────────────────────────────────────────────
    if (method === "GET" && path === "/api/v5/alias/options") {
      const hostname = url.searchParams.get("hostname") ?? "";
      // Derive a prefix suggestion from the hostname (strip www.)
      const prefix_suggestion = hostname
        .replace(/^www\./, "")
        .split(".")[0]
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "");

      const suffix = `@${env.DOMAIN}`;
      const signed = await signSuffix(suffix, env.SIGNING_SECRET);

      // Check if there's already a recommendation for this hostname
      let recommendation: { alias: string; hostname: string } | undefined;
      if (hostname) {
        const aliases = await getAllAliases(env.ALLOWED_ALIASES);
        const match = aliases.find(
          (a) => a.enabled && a.note?.includes(`hostname:${hostname}`),
        );
        if (match) {
          recommendation = { alias: match.email, hostname };
        }
      }

      const response: Record<string, unknown> = {
        can_create: true,
        prefix_suggestion,
        suffixes: [
          {
            suffix,
            signed_suffix: signed,
            is_custom: true,
            is_premium: false,
          },
        ],
      };
      if (recommendation) response.recommendation = recommendation;
      return json(response);
    }

    // ── POST /api/v3/alias/custom/new ─────────────────────────────────────────
    if (method === "POST" && path === "/api/v3/alias/custom/new") {
      let body: Record<string, unknown>;
      try {
        body = (await request.json()) as Record<string, unknown>;
      } catch {
        return err("request body cannot be empty");
      }

      const prefix = (body.alias_prefix as string | undefined)?.trim().toLowerCase();
      if (!prefix) return err("alias_prefix is required");
      if (!/^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$/.test(prefix)) {
        return err(
          "alias_prefix may only contain letters, digits, dots, dashes and underscores",
        );
      }

      const signedSuffix = body.signed_suffix as string | undefined;
      if (!signedSuffix) return err("signed_suffix is required");

      const suffix = await verifySuffix(signedSuffix, env.SIGNING_SECRET);
      if (!suffix) return err("signed_suffix is invalid or has been tampered with");

      const email = `${prefix}${suffix}`;
      const existing = await env.ALLOWED_ALIASES.get(email);
      if (existing !== null) return err(`${email} already exists`, 409);

      const hostname = url.searchParams.get("hostname") ?? null;
      const note = (body.note as string | undefined) ?? (hostname ? `hostname:${hostname}` : null);
      const name = (body.name as string | undefined) ?? null;
      const id = await nextId(env.ALLOWED_ALIASES);
      const now = Math.floor(Date.now() / 1000);

      const record: AliasRecord = {
        id,
        email,
        name,
        note,
        enabled: true,
        creation_timestamp: now,
        nb_forward: 0,
        nb_block: 0,
        nb_reply: 0,
        pinned: false,
      };

      await env.ALLOWED_ALIASES.put(email, JSON.stringify(record));
      return json(aliasToSLFormat(record, mailboxId, env.USER_EMAIL), 201);
    }

    // ── POST /api/alias/random/new ────────────────────────────────────────────
    if (method === "POST" && path === "/api/alias/random/new") {
      let note: string | null = null;
      try {
        const body = (await request.json()) as Record<string, unknown>;
        note = (body.note as string | undefined) ?? null;
      } catch {
        // body is optional
      }

      const hostname = url.searchParams.get("hostname");
      if (hostname && !note) note = `hostname:${hostname}`;

      const mode = url.searchParams.get("mode") ?? "word";
      let prefix: string;
      if (mode === "uuid") {
        prefix = randomHex(4) + "-" + randomHex(2) + "-" + randomHex(2) + "-" + randomHex(6);
      } else {
        // word mode: two words + random 3-digit number
        prefix = `${randomWord()}.${randomWord()}${randomInt(900) + 100}`;
      }

      const email = `${prefix}@${env.DOMAIN}`;
      const id = await nextId(env.ALLOWED_ALIASES);
      const now = Math.floor(Date.now() / 1000);

      const record: AliasRecord = {
        id,
        email,
        name: null,
        note,
        enabled: true,
        creation_timestamp: now,
        nb_forward: 0,
        nb_block: 0,
        nb_reply: 0,
        pinned: false,
      };

      await env.ALLOWED_ALIASES.put(email, JSON.stringify(record));
      return json(aliasToSLFormat(record, mailboxId, env.USER_EMAIL), 201);
    }

    // ── GET /api/v2/aliases ───────────────────────────────────────────────────
    if (method === "GET" && path === "/api/v2/aliases") {
      const pageId = parseInt(url.searchParams.get("page_id") ?? "0", 10);
      const enabledFilter = url.searchParams.get("enabled");
      const disabledFilter = url.searchParams.get("disabled");
      const pinnedFilter = url.searchParams.get("pinned");

      let aliases = await getAllAliases(env.ALLOWED_ALIASES);

      if (enabledFilter !== null)  aliases = aliases.filter((a) => a.enabled && !a.pinned);
      if (disabledFilter !== null) aliases = aliases.filter((a) => !a.enabled);
      if (pinnedFilter !== null)   aliases = aliases.filter((a) => a.pinned);

      const PAGE_SIZE = 20;
      const page = aliases.slice(pageId * PAGE_SIZE, (pageId + 1) * PAGE_SIZE);

      return json({ aliases: page.map((a) => aliasToSLFormat(a, mailboxId, env.USER_EMAIL)) });
    }

    // ── Routes with :alias_id ─────────────────────────────────────────────────
    // Match /api/aliases/:id or /api/aliases/:id/toggle
    const aliasMatch = path.match(/^\/api\/aliases\/(\d+)(\/[a-z]+)?$/);
    if (aliasMatch) {
      const aliasId = parseInt(aliasMatch[1], 10);
      const subRoute = aliasMatch[2] ?? "";

      // GET /api/aliases/:id
      if (method === "GET" && !subRoute) {
        const record = await getAliasById(env.ALLOWED_ALIASES, aliasId);
        if (!record) return err("Alias not found", 404);
        return json(aliasToSLFormat(record, mailboxId, env.USER_EMAIL));
      }

      // DELETE /api/aliases/:id
      if (method === "DELETE" && !subRoute) {
        const record = await getAliasById(env.ALLOWED_ALIASES, aliasId);
        if (!record) return err("Alias not found", 404);
        await env.ALLOWED_ALIASES.delete(record.email);
        return json({ deleted: true });
      }

      // POST /api/aliases/:id/toggle
      if (method === "POST" && subRoute === "/toggle") {
        const record = await getAliasById(env.ALLOWED_ALIASES, aliasId);
        if (!record) return err("Alias not found", 404);
        record.enabled = !record.enabled;
        await env.ALLOWED_ALIASES.put(record.email, JSON.stringify(record));
        return json({ enabled: record.enabled });
      }

      // PATCH /api/aliases/:id
      if (method === "PATCH" && !subRoute) {
        const record = await getAliasById(env.ALLOWED_ALIASES, aliasId);
        if (!record) return err("Alias not found", 404);

        let body: Record<string, unknown> = {};
        try { body = (await request.json()) as Record<string, unknown>; } catch { /* optional */ }

        if ("note"   in body) record.note   = (body.note as string | null) ?? null;
        if ("name"   in body) record.name   = (body.name as string | null) ?? null;
        if ("pinned" in body) record.pinned = Boolean(body.pinned);

        await env.ALLOWED_ALIASES.put(record.email, JSON.stringify(record));
        return json(aliasToSLFormat(record, mailboxId, env.USER_EMAIL));
      }
    }

    // ── GET /api/v2/mailboxes ─────────────────────────────────────────────────
    if (method === "GET" && path === "/api/v2/mailboxes") {
      return json({
        mailboxes: [
          {
            id: mailboxId,
            email: env.USER_EMAIL,
            default: true,
            creation_timestamp: 0,
            nb_alias: (await getAllAliases(env.ALLOWED_ALIASES)).length,
            verified: true,
          },
        ],
      });
    }

    // ── GET /api/v2/setting/domains ───────────────────────────────────────────
    if (method === "GET" && path === "/api/v2/setting/domains") {
      return json([{ domain: env.DOMAIN, is_custom: true }]);
    }

    // ── GET /api/setting ──────────────────────────────────────────────────────
    if (method === "GET" && path === "/api/setting") {
      return json({
        alias_generator: "word",
        notification: false,
        random_alias_default_domain: env.DOMAIN,
        sender_format: "AT",
        random_alias_suffix: "random_string",
      });
    }

    // ── POST /api/sync ────────────────────────────────────────────────────────
    // Body (JSON): { sl_api_key: string, sl_base_url?: string }
    // Fetches all aliases from the real SimpleLogin API and upserts them into KV.
    if (method === "POST" && path === "/api/sync") {
      let body: Record<string, unknown>;
      try {
        body = (await request.json()) as Record<string, unknown>;
      } catch {
        return err("request body cannot be empty");
      }

      const slApiKey = (body.sl_api_key as string | undefined)?.trim();
      if (!slApiKey) return err("sl_api_key is required");

      const slBaseUrl = (
        (body.sl_base_url as string | undefined)?.replace(/\/$/, "") ??
        env.SL_BASE_URL?.replace(/\/$/, "") ??
        "https://app.simplelogin.io"
      );

      try {
        const result = await syncWithSimpleLogin(slApiKey, slBaseUrl, env.ALLOWED_ALIASES);
        return json(result);
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        return err(`Sync failed: ${message}`, 502);
      }
    }

    return err("Not found", 404);
  },
};
