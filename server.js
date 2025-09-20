// server.js
import express from "express";
import cors from "cors";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";

const app = express();
app.use(express.json());

// CORS (restringe si quieres con tu dominio del front)
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";
app.use(cors({ origin: ALLOWED_ORIGIN }));

// Supabase
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE } = process.env;
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE) {
  console.error("❌ Faltan SUPABASE_URL o SUPABASE_SERVICE_ROLE");
  process.exit(1);
}
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE);

// Utils
function genNonce(len = 24) {
  return crypto.randomBytes(len).toString("base64url");
}

// Healthcheck
app.get("/healthz", (_req, res) => res.send("ok"));

// Nonce + mensaje a firmar
app.get("/auth/nonce", (_req, res) => {
  const nonce = genNonce();
  const now = new Date().toISOString();
  const message =
    `Inicia sesión con tu wallet (SIWS)\n` +
    `Dominio: auth-backend\n` +
    `Fecha: ${now}\n` +
    `Nonce: ${nonce}\n` +
    `\nAl firmar confirmas que controlas esta wallet.`;
  res.json({ nonce, message });
});

// Verificar firma y comprobar en Supabase
app.post("/auth/verify", async (req, res) => {
  try {
    const { publicKey, signature, message } = req.body;
    if (!publicKey || !signature || !message) {
      return res.status(400).json({ error: "Faltan publicKey/signature/message" });
    }

    const sigUint8 = new Uint8Array(signature);           // Array -> Uint8Array
    const msgUint8 = new TextEncoder().encode(message);   // string -> bytes
    const pubKeyUint8 = bs58.decode(publicKey);           // base58 -> bytes

    const ok = nacl.sign.detached.verify(msgUint8, sigUint8, pubKeyUint8);
    if (!ok) return res.status(401).json({ error: "Firma inválida" });

    // Buscar usuario por wallet
    const { data: user, error } = await supabase
      .from("users")
      .select("id, name, handle, image_url")
      .eq("wallet", publicKey)
      .maybeSingle();

    if (error) {
      console.error(error);
      return res.status(500).json({ error: "Error consultando Supabase" });
    }

    if (!user) return res.json({ registered: false });
    return res.json({ registered: true, profile: user });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Error interno" });
  }
});

// Escuchar SIEMPRE en 0.0.0.0 y en el PORT que da Railway
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () =>
  console.log(`✅ Auth backend escuchando en :${PORT}`)
);
