import { generateKeyPair, exportJWK, exportPKCS8 } from "jose";
import fs from "fs";
import path from "path";

const KEYS_DIR = path.join(process.cwd(), "keys");
fs.mkdirSync(KEYS_DIR, { recursive: true });

const { privateKey, publicKey } = await generateKeyPair("RS256", { modulusLength: 2048 });
const jwk = await exportJWK(publicKey);
jwk.kid = cryptoRandom(8);
jwk.alg = "RS256";
jwk.use = "sig";

const pkcs8 = await exportPKCS8(privateKey);

fs.writeFileSync(path.join(KEYS_DIR, "private.pem"), pkcs8);
fs.writeFileSync(path.join(KEYS_DIR, "jwks.json"), JSON.stringify({ keys: [jwk] }, null, 2));

console.log("✅ Generated keys/ (private.pem + jwks.json). kid:", jwk.kid);

function cryptoRandom(bytes) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";
  for (let i = 0; i < bytes; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
  return out;
}
