const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
const mongoose = require("mongoose");

const app = express();

// 🔥 IMPORTANT POUR RENDER
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;

// ==========================
// MongoDB connection
// ==========================
async function startServer() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log("MongoDB connecté");

    app.listen(PORT, () => {
      console.log(`Serveur lancé sur http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error("Erreur démarrage serveur:", err);
  }
}

// ==========================
// Schema MongoDB
// ==========================
const secretSchema = new mongoose.Schema({
  secret: String,
  pinHash: String,
  attempts: { type: Number, default: 0 },
  locked: { type: Boolean, default: false },
  consumed: { type: Boolean, default: false },
  expiresAt: Number
});

const Secret = mongoose.model("Secret", secretSchema);

// ==========================
// Middleware
// ==========================
app.use(express.json({ limit: "1mb" }));
app.use(express.static("public"));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Trop de requêtes. Réessaie plus tard." }
});

app.use(limiter);

// ==========================
// Helpers
// ==========================
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

// ==========================
// Nettoyage automatique
// ==========================
setInterval(async () => {
  const now = Date.now();
  await Secret.deleteMany({ expiresAt: { $lte: now } });
}, 60 * 1000);

// ==========================
// Routes
// ==========================

// Page principale
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Page lecture
app.get("/view/:id", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Création secret
app.post("/api/secret", async (req, res) => {
  try {
    const { secret, pin, expiresInMinutes } = req.body;

    if (!secret || !secret.trim()) {
      return res.status(400).json({ error: "Le secret est obligatoire." });
    }

    if (!isValidPin(pin)) {
      return res.status(400).json({ error: "PIN invalide (6 chiffres)." });
    }

    const pinHash = await bcrypt.hash(pin, 10);

    const newSecret = await Secret.create({
      secret: secret.trim(),
      pinHash,
      expiresAt: Date.now() + getExpirationMs(expiresInMinutes)
    });

    res.json({
      ok: true,
      id: newSecret._id,
      link: `/view/${newSecret._id}`
    });

  } catch (err) {
    res.status(500).json({ error: "Erreur serveur." });
  }
});

// Lecture secret
app.post("/api/secret/:id/read", async (req, res) => {
  try {
    const { pin } = req.body;

    const item = await Secret.findById(req.params.id);

    if (!item) {
      return res.status(404).json({ error: "Secret introuvable." });
    }

    if (item.expiresAt <= Date.now()) {
      await Secret.deleteOne({ _id: item._id });
      return res.status(410).json({ error: "Secret expiré." });
    }

    if (item.locked) {
      return res.status(423).json({ error: "Bloqué après 3 erreurs." });
    }

    if (item.consumed) {
      return res.status(410).json({ error: "Déjà consulté." });
    }

    if (!isValidPin(pin)) {
      return res.status(400).json({ error: "PIN invalide." });
    }

    const valid = await bcrypt.compare(pin, item.pinHash);

    if (!valid) {
      item.attempts += 1;

      if (item.attempts >= 3) {
        item.locked = true;
      }

      await item.save();

      return res.status(403).json({
        error: `PIN incorrect. ${3 - item.attempts} essai(s) restant(s).`
      });
    }

    item.consumed = true;
    await item.save();

    res.json({
      ok: true,
      secret: item.secret
    });

  } catch (err) {
    res.status(500).json({ error: "Erreur serveur." });
  }
});

// 404
app.use((req, res) => {
  res.status(404).json({ error: "Route introuvable" });
});

// ==========================
startServer();