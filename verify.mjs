#!/usr/bin/env node
// Wizard Watcher proof verifier. Checks a channel's proof file, or a signed evidence file, without trusting Wizard
// Watcher:
//
//   node verify.mjs proof.json [--key key.pem] [--offline]
//   node verify.mjs evidence.json [--key key.pem] [--offline]
//   node verify.mjs compare ours.json theirs.json [--key key.pem] [--offline]
//
// For an evidence file, first: it's signed by Wizard Watcher's key; every message's content (sender, time, reply,
// recipient, text, file) hashes to its receipt; and no message in the period is missing. Then the proof checks below.
//
// 1. The receipts (each message's sequence number and SHA-256 receipt hash) chain up to the channel's recorded
//    chain value, with nothing missing or out of order.
// 2. That chain value is in the checkpoint's Merkle tree (RFC 6962), by its audit path.
// 3. The checkpoint note is signed by Wizard Watcher's key (pinned below; --key to use another file).
// 4. Unless --offline: the note's hash, signature and key are in Sigstore's public Rekor log, and when Rekor took it.
//
// For a channel on a cross-company link, the evidence file also carries each shared message's receipt on the link and
// the link's own chain, which is published in the same checkpoints. "compare" checks two companies' evidence files for
// the same link: each verifies on its own, and the shared messages are identical, receipt for receipt.
//
// If Wizard Watcher later changed or removed any message, its chain, and so the published checkpoint, would no longer
// match. Plain JavaScript, no dependencies, Node 20 or later. See README.md. MIT licensed.

import { readFileSync } from "node:fs";
import { webcrypto as crypto } from "node:crypto";

/** Wizard Watcher's checkpoint signing key (also at https://relay.wizardwatcher.ai/log/key). */
export const PINNED_KEY = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbKDGJXbvaNRVf8rpY6Ukz20fQuxn
aPW+VUnDKhH/KdTyqdZiqFrAmF+Wkyv9c5KnKahwBJvipY6Jl7bxZ+QZvg==
-----END PUBLIC KEY-----
`;

const enc = new TextEncoder();
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => {
  if (!/^([0-9a-f]{2})*$/.test(h)) throw new Error(`not lowercase hex: ${h.slice(0, 20)}`);
  return Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
};
const unb64 = (s) => Uint8Array.from(Buffer.from(s, "base64"));
async function sha256(...parts) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", Buffer.concat(parts.map((p) => Buffer.from(p)))));
}
const node = (l, r) => sha256(Uint8Array.of(1), l, r);

/** RFC 9162 2.1.3.2: the root an audit path leads to, or null. */
async function rootFromProof(leaf, index, size, path) {
  if (index >= size) return null;
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of path) {
    if (sn === 0) return null;
    if (fn % 2 === 1 || fn === sn) {
      r = await node(p, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn >>= 1;
        sn >>= 1;
      }
    } else r = await node(r, p);
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 ? r : null;
}

/** A v2 note (it starts with wizardwatcher.ai, or wizardwatcher.si before the move to .ai), or a v1 note
 * (checkpoint 1 only), which also gave the channel count. */
function parseNote(note) {
  const m =
    /^(?:wizardwatcher\.(?:ai|si)\/log\/v2\ncheckpoint (\d+)|wizardwatcher\.si\/log\/v1\ncheckpoint (\d+)\nchannels (\d+))\nroot ([0-9a-f]{64})\nprevious ([0-9a-f]{64}|none)\ntime (\S+)\n$/.exec(note);
  if (!m) throw new Error("the checkpoint note isn't in Wizard Watcher's format");
  return { n: Number(m[1] ?? m[2]), channels: m[3] === undefined ? undefined : Number(m[3]), root: m[4], previous: m[5], time: m[6] };
}

/** ASN.1 DER ECDSA signature to the raw r || s WebCrypto wants. */
function derToRaw(der) {
  if (der[0] !== 0x30) throw new Error("not a DER signature");
  let at = 2;
  const read = () => {
    if (der[at] !== 0x02) throw new Error("not a DER signature");
    const len = der[at + 1];
    const v = der.slice(at + 2, at + 2 + len);
    at += 2 + len;
    const out = new Uint8Array(32);
    const t = v.slice(Math.max(0, v.length - 32));
    out.set(t, 32 - t.length);
    return out;
  };
  return Uint8Array.from([...read(), ...read()]);
}

const pemBody = (pem) => pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");

/** What a receipt hash is the SHA-256 of: these fields, in this order, joined by "\n" (relay/src/verifiable-log.ts). */
function receiptText(channel, m) {
  return [
    channel,
    m.seq,
    m.from,
    m.sent_at,
    m.reply_to ?? "",
    m.text,
    ...(m.to !== null ? [`to:${m.to}`] : []),
    ...(m.file ? [`file:${m.file.sha256}:${m.file.size}:${m.file.name}`] : []),
  ].join("\n");
}

async function signedBy(key, text, signature) {
  const pub = await crypto.subtle.importKey("spki", unb64(pemBody(key)), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, pub, derToRaw(unb64(signature)), enc.encode(text));
}

/** An evidence file: its signature and every message against its receipt, then the proof checks. */
export async function verifyEvidence(file, opts = {}) {
  const key = opts.key ?? PINNED_KEY;
  const out = [];
  const check = (ok, what) => (out.push({ ok: !!ok, what }), !!ok);
  if (file.format !== "wizardwatcher-evidence-file/1") return check(false, "This isn't a Wizard Watcher evidence file."), out;
  check(await signedBy(key, file.evidence, file.signature), `The evidence is signed by ${key === PINNED_KEY ? "Wizard Watcher's pinned key" : "the given key"}.`);
  const ev = JSON.parse(file.evidence);
  const id = ev.channel.id;
  let bad = [];
  for (const m of ev.messages) {
    const h = hex(await sha256(enc.encode(receiptText(id, m))));
    if (h !== m.hash || ev.receipts[m.seq - 1]?.hash !== h) bad.push(m.seq);
  }
  check(
    !bad.length,
    bad.length
      ? `Every message matches its receipt: no, ${bad.length === 1 ? "message" : "messages"} ${bad.slice(0, 10).map((s) => `#${s}`).join(", ")}${bad.length > 10 ? "…" : ""} ${bad.length === 1 ? "doesn't" : "don't"}.`
      : `All ${ev.messages.length} messages in the period match their receipts (sender, time, reply, recipient, text and file).`,
  );
  const seqs = ev.messages.map((m) => m.seq);
  const contiguous = seqs.every((s, i) => i === 0 || s === seqs[i - 1] + 1);
  check(
    contiguous && (seqs.length === 0 || (seqs[0] === ev.messages_first && seqs[seqs.length - 1] === ev.messages_last)),
    seqs.length ? `No message between #${seqs[0]} and #${seqs[seqs.length - 1]} is left out.` : "The period has no messages.",
  );
  const proof = { format: "wizardwatcher-proof/1", channel: ev.channel, receipts: ev.receipts, leaf: ev.proof.leaf, checkpoint: ev.proof.checkpoint };
  const channelChecks = await verify(proof, { ...opts, key });
  return [...out, ...channelChecks, ...(ev.link ? await verifyLink(ev, { ...opts, key }) : [])];
}

/** A linked channel's evidence: each shared message against its receipt on the link, and the link's chain in the log. */
async function verifyLink(ev, opts) {
  const out = [];
  const check = (ok, what) => (out.push({ ok: !!ok, what }), !!ok);
  const lk = ev.link;
  const shared = ev.messages.filter((m) => m.link);
  const bad = [];
  for (const m of shared) {
    const h = hex(await sha256(enc.encode(receiptText(lk.id, { seq: m.link.seq, from: m.link.from, sent_at: m.link.sent_at, reply_to: m.link.reply_to, text: m.text, to: null, file: null }))));
    const listed = lk.receipts[m.link.seq - 1];
    if (h !== m.link.hash || (listed && (listed.seq !== m.link.seq || listed.hash !== h))) bad.push(m.seq);
  }
  check(
    !bad.length,
    bad.length
      ? `Shared messages match their link receipts: no, ${bad.slice(0, 10).map((s) => `#${s}`).join(", ")} ${bad.length === 1 ? "doesn't" : "don't"}.`
      : `All ${shared.length} shared messages in the period match their receipts on link ${lk.id} (with ${lk.other}).`,
  );
  if (!lk.proof) {
    out.push({ ok: true, what: `Not checked yet: the link's chain against the public log (${lk.note ?? "no proof in this file"}). Export again later.` });
    return out;
  }
  // The same checkpoint as the channel's, so Rekor was already checked above.
  const linkChecks = await verify(
    { format: "wizardwatcher-proof/1", channel: { id: lk.id }, receipts: lk.receipts, leaf: lk.proof.leaf, checkpoint: lk.proof.checkpoint },
    { ...opts, offline: true },
  );
  return [...out, ...linkChecks.map((r) => ({ ...r, what: `Link: ${r.what.replace(/^The channel is in/, "The link is in")}` }))];
}

/**
 * Two evidence files from the two copies of one link: each verifies on its own, they're one from each side, and the
 * shared messages they hold are the same, receipt for receipt.
 */
export async function compareEvidence(fileA, fileB, opts = {}) {
  const out = [];
  const check = (ok, what) => (out.push({ ok: !!ok, what }), !!ok);
  const ra = await verifyEvidence(fileA, opts);
  const rb = await verifyEvidence(fileB, opts);
  const ea = JSON.parse(fileA.evidence);
  const eb = JSON.parse(fileB.evidence);
  if (!check(ea.link && eb.link, "Both files are from channels on a cross-company link.")) return [...ra, ...rb, ...out];
  check(
    ea.link.id === eb.link.id && ea.link.side !== eb.link.side,
    `Both are copies of link ${ea.link.id}, one from each side (${eb.link.other} and ${ea.link.other}).`,
  );
  const n = Math.min(ea.link.receipts.length, eb.link.receipts.length);
  const first = Array.from({ length: n }, (_, i) => i).find((i) => ea.link.receipts[i].hash !== eb.link.receipts[i].hash || ea.link.receipts[i].seq !== eb.link.receipts[i].seq);
  check(first === undefined, first === undefined ? `Both copies hold the same ${n} shared messages, receipt for receipt.` : `The copies differ from shared message #${first + 1}.`);
  const inB = new Map(eb.messages.filter((m) => m.link).map((m) => [m.link.seq, m]));
  const both = ea.messages.filter((m) => m.link && inB.has(m.link.seq));
  const differ = both.filter((m) => inB.get(m.link.seq).link.hash !== m.link.hash || inB.get(m.link.seq).text !== m.text);
  check(
    !differ.length,
    differ.length
      ? `Shared messages in both periods are identical: no, link #${differ.slice(0, 10).map((m) => m.link.seq).join(", #")} differ.`
      : `The ${both.length} shared messages in both periods have the same text and receipt in both copies.`,
  );
  return [...ra.map((r) => ({ ...r, what: `First file: ${r.what}` })), ...rb.map((r) => ({ ...r, what: `Second file: ${r.what}` })), ...out];
}

/**
 * Runs every check; returns [{ ok, what }] in order. `fetchImpl` is for tests; `offline` skips Rekor.
 */
export async function verify(proof, { key = PINNED_KEY, offline = false, fetchImpl = fetch } = {}) {
  const out = [];
  const check = (ok, what) => (out.push({ ok: !!ok, what }), !!ok);
  if (proof.format !== "wizardwatcher-proof/1") return check(false, "This isn't a Wizard Watcher proof file (format wizardwatcher-proof/1)."), out;
  const id = proof.channel.id;

  // 1. Receipts chain to the recorded value.
  let chain = hex(await sha256(enc.encode(`wizardwatcher-chain\n${id}`)));
  let expected = 1;
  let gap = null;
  for (const r of proof.receipts) {
    if (r.seq !== expected) {
      gap = `expected message #${expected}, found #${r.seq}`;
      break;
    }
    chain = hex(await sha256(unhex(chain), unhex(r.hash)));
    expected++;
  }
  check(!gap && expected - 1 === proof.leaf.seq, gap ? `Receipts are complete: no, ${gap}.` : `Receipts are complete: messages #1 to #${proof.leaf.seq}, none missing.`);
  check(chain === proof.leaf.chain, `The receipts chain to the recorded value ${proof.leaf.chain.slice(0, 16)}…`);

  // 2. The leaf is in the checkpoint's tree.
  const note = parseNote(proof.checkpoint.note);
  const leaf = await sha256(Uint8Array.of(0), enc.encode(`${id}\n${proof.leaf.seq}\n${proof.leaf.chain}`));
  const root = await rootFromProof(leaf, proof.leaf.index, proof.leaf.size, proof.leaf.path.map(unhex));
  // v1 notes said how many channels the tree has; v2 notes keep that private, and the proof carries it. The size only
  // shapes the audit path: a wrong one can't make a channel look included, because the leaf is computed here and leaves
  // and inner nodes are hashed with different prefixes.
  if (note.channels !== undefined) check(note.channels === proof.leaf.size, `The checkpoint covers ${note.channels} channels, as the proof says.`);
  check(root && hex(root) === note.root, `The channel is in checkpoint ${note.n}'s Merkle tree (root ${note.root.slice(0, 16)}…).`);

  // 3. The note is signed by Wizard Watcher's key.
  const spki = unb64(pemBody(key));
  const pub = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const sigOk = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    pub,
    derToRaw(unb64(proof.checkpoint.signature)),
    enc.encode(proof.checkpoint.note),
  );
  check(sigOk, `Checkpoint ${note.n} (${note.time}) is signed by ${key === PINNED_KEY ? "Wizard Watcher's pinned key" : "the given key"}.`);

  // 4. Rekor has it.
  if (offline) return out;
  const rk = proof.checkpoint.rekor;
  if (!rk) return check(false, "The checkpoint is in Rekor: not yet (it's published within 15 minutes; download the proof again later)."), out;
  try {
    const res = await fetchImpl(`https://rekor.sigstore.dev/api/v1/log/entries/${rk.uuid}`, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(`Rekor answered ${res.status}`);
    const entry = Object.values(await res.json())[0];
    const body = JSON.parse(Buffer.from(entry.body, "base64").toString("utf8"));
    const noteHash = hex(await sha256(enc.encode(proof.checkpoint.note)));
    const keyInRekor = Buffer.from(body.spec.signature.publicKey.content, "base64").toString("utf8");
    check(
      body.kind === "hashedrekord" &&
        body.spec.data.hash.value === noteHash &&
        body.spec.signature.content === proof.checkpoint.signature &&
        pemBody(keyInRekor) === pemBody(key),
      `Rekor entry ${entry.logIndex} holds this checkpoint, signed by the same key, since ${new Date(entry.integratedTime * 1000).toISOString()}.`,
    );
  } catch (e) {
    check(false, `The checkpoint is in Rekor: couldn't check (${e.message}). Run with --offline to skip.`);
  }
  return out;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const ki = args.indexOf("--key");
  const key = ki >= 0 ? readFileSync(args[ki + 1], "utf8") : PINNED_KEY;
  const plain = args.filter((a, i) => !a.startsWith("--") && (ki < 0 || i !== ki + 1));
  if (plain[0] === "compare") {
    if (plain.length !== 3) {
      console.error("usage: node verify.mjs compare ours.json theirs.json [--key key.pem] [--offline]");
      process.exit(2);
    }
    const [a, b] = plain.slice(1).map((f) => JSON.parse(readFileSync(f, "utf8")));
    const results = await compareEvidence(a, b, { key, offline: args.includes("--offline") });
    for (const r of results) console.log(`${r.ok ? "✓" : "✗"} ${r.what}`);
    const ok = results.every((r) => r.ok);
    console.log(ok ? "\nVerified: the two copies match." : "\nNOT verified.");
    process.exit(ok ? 0 : 1);
  }
  const file = plain[0];
  if (!file) {
    console.error("usage: node verify.mjs proof-or-evidence.json [--key key.pem] [--offline]\n       node verify.mjs compare ours.json theirs.json");
    process.exit(2);
  }
  const parsed = JSON.parse(readFileSync(file, "utf8"));
  const evidence = parsed.format === "wizardwatcher-evidence-file/1";
  const channel = evidence ? JSON.parse(parsed.evidence).channel : parsed.channel;
  console.log(`${evidence ? "Evidence file for channel" : "Channel"} ${channel.name ?? ""} (${channel.id})`);
  const opts = { key, offline: args.includes("--offline") };
  const results = evidence ? await verifyEvidence(parsed, opts) : await verify(parsed, opts);
  for (const r of results) console.log(`${r.ok ? "✓" : "✗"} ${r.what}`);
  const ok = results.every((r) => r.ok);
  console.log(ok ? "\nVerified." : "\nNOT verified.");
  process.exit(ok ? 0 : 1);
}
