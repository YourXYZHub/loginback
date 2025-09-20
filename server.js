// server.js
import express from "express";
import cors from "cors";
import nacl from "tweetnacl";
import bs58 from "bs58";
import { createClient } from "@supabase/supabase-js";

const app = express();
app.use(cors());
app.use(express.json());

// === ENV ===
// Pon estas variables en tu entorno (Railway/Render/.env):
// SUPABASE_URL=...
// SUPABASE_SERVICE_ROLE=...  (o ANON si solo haces SELECT con RLS correcto)
// PORT=3000
const { SUPABASE_URL, SUPABASE_SERVICE_ROLE, PORT = 3000 } = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE) {
  console.warn("⚠️  Faltan variables SUPABASE_URL o SUPABASE_SERVICE_ROLE");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE);

// Util simple para generar nonce
function genNonce(len = 16) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "";
  for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

// Ruta para pedir nonce (y mensaje a firmar)
app.get("/auth/nonce", (req, res) => {
  const nonce = genNonce();
  const message =
    `Inicia sesión con tu wallet (SIWS)\n` +
    `Dominio: demo-login\n` +
    `Nonce: ${nonce}\n` +
    `Fecha: ${new Date().toISOString()}\n` +
    `\nAl firmar confirmas que controlas esta wallet.`;
  res.json({ nonce, message });
});

// Ruta para verificar firma y chequear registro
app.post("/auth/verify", async (req, res) => {
  try {
    const { publicKey, signature, message } = req.body;
    if (!publicKey || !signature || !message) {
      return res.status(400).json({ error: "Faltan campos publicKey/signature/message" });
    }

    // Verificar firma con tweetnacl
    // signature llega como array (desde el front). Convertimos a Uint8Array:
    const sigUint8 = new Uint8Array(signature);
    const msgUint8 = new TextEncoder().encode(message);
    const pubKeyUint8 = bs58.decode(publicKey);

    const ok = nacl.sign.detached.verify(msgUint8, sigUint8, pubKeyUint8);
    if (!ok) {
      return res.status(401).json({ error: "Firma inválida" });
    }

    // Si la firma es válida, comprobamos si la wallet existe en Supabase
    const { data, error } = await supabase
      .from("users")
      .select("id")
      .eq("wallet", publicKey)
      .maybeSingle();

    if (error) {
      console.error(error);
      return res.status(500).json({ error: "Error consultando Supabase" });
    }

    const registered = !!data;
    return res.json({ registered });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Error interno" });
  }
});

app.listen(PORT, () => {
  console.log(`Auth server escuchando en http://localhost:${PORT}`);
});
