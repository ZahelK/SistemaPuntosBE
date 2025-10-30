import express from 'express';
import cors from 'cors';
import { createClient } from '@supabase/supabase-js';
import dotenv from "dotenv";


dotenv.config();
const app = express();
app.use(express.json());
app.use(cors({ origin: 'http://localhost:5173', credentials: true }));

const PORT = process.env.PORT || 3000;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

// Configura Supabase con tu URL y SERVICE_ROLE_KEY
const supabase = createClient(
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY // clave privada (no expongas esta)
);

// --- LOGIN ---
app.post("/login", async (req, res) => {
  const { email, password, fingerprint } = req.body;

  // 1️⃣ Iniciar sesión
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error || !data.user)
    return res.status(401).json({ error: "Correo o contraseña incorrectos" });

  const user = data.user;

  // 2️⃣ Buscar si ya hay una huella registrada
  const { data: existing, error: selectErr } = await supabase
    .from("device_fingerprints")
    .select("*")
    .eq("user_id", user.id)
    .single();

  if (selectErr && selectErr.code !== "PGRST116") {
    return res.status(500).json({ error: "Error al verificar dispositivo" });
  }

  // 3️⃣ Si no hay huella → registrar la actual
  if (!existing) {
    const { error: insertErr } = await supabase
      .from("device_fingerprints")
      .insert({ user_id: user.id, fingerprint });

    if (insertErr) return res.status(500).json({ error: "Error al registrar dispositivo" });
    return res.json({ message: "Primer acceso desde este dispositivo autorizado", user });
  }

  // 4️⃣ Si ya hay huella, verificar coincidencia
  if (existing.fingerprint !== fingerprint) {
    return res
      .status(403)
      .json({ error: "Acceso bloqueado: este usuario solo puede iniciar sesión desde su dispositivo autorizado." });
  }

  res.json({ message: "Inicio de sesión exitoso", user });
});

app.listen(PORT, () => console.log("✅ Servidor en http://localhost:3000"));