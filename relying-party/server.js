import "dotenv/config";
import express from "express";
import cors from "cors";
import path from "path";
import { createRemoteJWKSet, jwtVerify } from "jose";

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: false }));

const PORT = process.env.PORT || 4002;
const EXPECTED_ISS = process.env.EXPECTED_ISS || "http://localhost:4001";
const RP_ID = process.env.RP_ID || "com.example.shop";
const JWKS_URL = process.env.ISSUER_JWKS_URL || `${EXPECTED_ISS}/.well-known/jwks.json`;

const JWKS = createRemoteJWKSet(new URL(JWKS_URL));

// Static demo UI
app.use(express.static(path.join(process.cwd(), "public")));

app.get("/health", (_req, res) => res.json({ ok: true, rp_id: RP_ID, iss_jwks: JWKS_URL }));

// POST /verify { assertion }
app.post("/verify", async (req, res) => {
  try {
    const { assertion } = req.body || {};
    if (!assertion) return res.status(400).json({ error: "assertion (JWT) required" });

    const { payload } = await jwtVerify(assertion, JWKS, {
      issuer: EXPECTED_ISS,
      audience: RP_ID
    });

    // payload.attrs contains selective disclosure (e.g. age_over_18: true)
    res.json({ valid: true, sub: payload.sub, attrs: payload.attrs || {}, iat: payload.iat, exp: payload.exp });
  } catch (e) {
    res.status(400).json({ valid: false, error: e.message });
  }
});

app.listen(PORT, () => console.log(`Relying Party listening on http://localhost:${PORT}`));
