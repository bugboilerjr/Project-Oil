import "dotenv/config";
import express from "express";
import cors from "cors";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { nanoid } from "nanoid";
import { importPKCS8, SignJWT } from "jose";

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: false }));

const PORT = process.env.PORT || 4001;
const ISSUER = process.env.ISSUER_BASEURL || `http://localhost:${PORT}`;
const HMAC_SECRET = process.env.HMAC_SECRET || "dev_secret_change_me";
const TOKEN_TTL_SECONDS = Number(process.env.TOKEN_TTL_SECONDS || 1800);

// Load keys & JWKS
const KEYS_DIR = path.join(process.cwd(), "keys");
const PRIVATE_PEM = fs.readFileSync(path.join(KEYS_DIR, "private.pem"), "utf8");
const JWKS = JSON.parse(fs.readFileSync(path.join(KEYS_DIR, "jwks.json"), "utf8"));
const KID = JWKS.keys[0].kid;

const privateKey = await importPKCS8(PRIVATE_PEM, "RS256");

// In-memory “database”
const users = new Map();   // user_id -> { dob }
const tokens = new Map();  // network_token -> { user_id, rp_id, ppid, exp }
const relyingParties = new Map([
  ["com.example.shop", { rp_id: "com.example.shop", name: "Example Shop" }]
]);

// Helpers
const hmacBase64Url = (key, data) =>
  crypto.createHmac("sha256", key).update(data).digest("base64url");

const calcAge = (dobStr) => {
  const now = new Date();
  const dob = new Date(`${dobStr}T00:00:00Z`);
  let age = now.getUTCFullYear() - dob.getUTCFullYear();
  const m = now.getUTCMonth() - dob.getUTCMonth();
  if (m < 0 || (m === 0 && now.getUTCDate() < dob.getUTCDate())) age--;
  return age;
};

// Health & JWKS
app.get("/health", (_req, res) => res.json({ ok: true, iss: ISSUER }));
app.get("/.well-known/jwks.json", (_req, res) => res.json(JWKS));

// 1) Enroll (simulate successful KYC)
app.post("/enroll", (req, res) => {
  const { dob } = req.body || {};
  if (!dob) return res.status(400).json({ error: "dob (YYYY-MM-DD) required" });
  const user_id = "usr_" + nanoid(16);
  users.set(user_id, { dob });
  res.json({ user_id });
});

// 2) Issue RP-scoped token + selective-disclosure JWT
app.post("/token", async (req, res) => {
  const { user_id, rp_id, claims = [] } = req.body || {};
  if (!users.has(user_id)) return res.status(404).json({ error: "unknown user_id" });
  if (!relyingParties.has(rp_id)) return res.status(404).json({ error: "unknown rp_id" });

  const ppid = hmacBase64Url(HMAC_SECRET, `${user_id}:${rp_id}`);
  const network_token = nanoid(24);
  const expMs = Date.now() + TOKEN_TTL_SECONDS * 1000;

  tokens.set(network_token, { user_id, rp_id, ppid, exp: expMs });

  const profile = users.get(user_id);
  const age = calcAge(profile.dob);
  const attrs = {};
  if (claims.includes("age_over_13")) attrs.age_over_13 = age >= 13;
  if (claims.includes("age_over_16")) attrs.age_over_16 = age >= 16;
  if (claims.includes("age_over_18")) attrs.age_over_18 = age >= 18;
  if (claims.includes("age_over_21")) attrs.age_over_21 = age >= 21;

  const jwt = await new SignJWT({ attrs })
    .setProtectedHeader({ alg: "RS256", kid: KID })
    .setIssuer(ISSUER)
    .setAudience(rp_id)
    .setSubject(ppid)
    .setIssuedAt()
    .setExpirationTime(TOKEN_TTL_SECONDS)
    .sign(privateKey);

  res.json({ ppid, network_token, assertion: jwt, exp: expMs });
});

// 3) Introspect (optional)
app.post("/introspect", (req, res) => {
  const { network_token } = req.body || {};
  const rec = tokens.get(network_token);
  if (!rec) return res.json({ active: false });
  const active = rec.exp > Date.now();
  res.json({ active, ppid: rec.ppid, rp_id: rec.rp_id, exp: rec.exp });
});

// 4) Revoke
app.post("/revoke", (req, res) => {
  const { network_token } = req.body || {};
  tokens.delete(network_token);
  res.json({ revoked: true });
});

app.listen(PORT, () => console.log(`Issuer Vault listening on ${ISSUER}`));
