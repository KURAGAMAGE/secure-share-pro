const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");

const app = express();
const PORT = process.env.PORT || 3000; // ✅ MODIFIÉ ICI

const secrets = new Map();

app.use(express.json({ limit: "1mb" }));
app.use(express.static("public"));

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Trop de requêtes. Réessaie plus tard." }
});

app.use(globalLimiter);

function isValidPin(pin) {
  return /^\d{6}$/.test(pin);
}

function getExpirationMs(value) {
  const minutes = Number(value);
  if (minutes === 5) return 5 * 60 * 1000;
  if (minutes === 10) return 10 * 60 * 1000;
  if (minutes === 30) return 30 * 60 * 1000;
  if (minutes === 60) return 60 * 60 * 1000;
  return 10 * 60 * 1000;
}

// Nettoyage automatique
setInterval(() => {
  const now = Date.now();

  for (const [id, item] of secrets.entries()) {
    if (item.expiresAt <= now) {
      secrets.delete(id);
    }
  }
}, 60 * 1000);

// Page principale
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Page lecture
app.get("/view/:id", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Création d’un secret
app.post("/api/secret", async (req, res) => {
  try {
    const { secret, pin, expiresInMinutes } = req.body;

    if (!secret || typeof secret !== "string" || !secret.trim()) {
      return res.status(400).json({ error: "Le secret est obligatoire." });
    }

    if (!isValidPin(pin)) {
      return res.status(400).json({ error: "Le PIN doit contenir exactement 6 chiffres." });
    }

    const id = crypto.randomUUID();
    const pinHash = await bcrypt.hash(pin, 10);
    const expiresAt = Date.now() + getExpirationMs(expiresInMinutes);

    secrets.set(id, {
      secret: secret.trim(),
      pinHash,
      attempts: 0,
      locked: false,
      consumed: false,
      expiresAt
    });

    return res.json({
      ok: true,
      id,
      link: `/view/${id}`
    });
  } catch (error) {
    return res.status(500).json({ error: "Erreur serveur." });
  }
});

// Lecture sécurisée
app.post("/api/secret/:id/read", async (req, res) => {
  try {
    const { pin } = req.body;
    const item = secrets.get(req.params.id);

    if (!item) {
      return res.status(404).json({ error: "Secret introuvable ou expiré." });
    }

    if (item.expiresAt <= Date.now()) {
      secrets.delete(req.params.id);
      return res.status(410).json({ error: "Secret introuvable ou expiré." });
    }

    if (item.locked) {
      return res.status(423).json({ error: "Secret bloqué après 3 erreurs." });
    }

    if (item.consumed) {
      return res.status(410).json({ error: "Secret déjà consulté." });
    }

    if (!isValidPin(pin)) {
      return res.status(400).json({ error: "Le PIN doit contenir exactement 6 chiffres." });
    }

    const valid = await bcrypt.compare(pin, item.pinHash);

    if (!valid) {
      item.attempts += 1;

      if (item.attempts >= 3) {
        item.locked = true;
        return res.status(423).json({ error: "Secret bloqué après 3 erreurs." });
      }

      return res.status(403).json({
        error: `PIN incorrect. Il reste ${3 - item.attempts} essai(s).`
      });
    }

    item.consumed = true;

    return res.json({
      ok: true,
      secret: item.secret
    });
  } catch (error) {
    return res.status(500).json({ error: "Erreur serveur." });
  }
});

// Route introuvable
app.use((req, res) => {
  res.status(404).json({ error: "Route introuvable" });
});

app.listen(PORT, () => {
  console.log(`Serveur lancé sur http://localhost:${PORT}`);
});