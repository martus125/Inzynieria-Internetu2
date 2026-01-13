import path from "path";
import { fileURLToPath } from "url";
import "dotenv/config";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import session from "express-session";
import bcrypt from "bcryptjs";

import { poolPromise, sql } from "./db.js";

const app = express();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(session({
  name: "olimp.sid",
  secret: process.env.SESSION_SECRET || "dev-secret",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    maxAge: 24 * 60 * 60 * 1000,
  }
}));


app.use(express.static(path.join(__dirname, "../FRONTED")));


app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: true,        // odbija origin z przeglądarki
  credentials: true,
}));


app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", secure: false },
  })
);

// odpowiedz czy backend zyje
app.get("/api/ping", (req, res) => res.json({ ok: true, msg: "Backend działa" }));

// healthcheck DB
app.get("/api/health", async (req, res) => {
  try {
    const pool = await poolPromise;
    const r = await pool.request().query("SELECT 1 AS result");
    res.json({ status: "ok", db: r.recordset[0].result });
  } catch (e) {
    res.status(500).json({ status: "error", error: e.message });
  }
});

// rejestracja
app.post("/api/auth/register", async (req, res) => {
  const { login, password } = req.body || {};
  if (!login || !password || password.length < 6) {
    return res.status(400).json({ error: "Podaj login i hasło (min. 6 znaków)." });
  }

  try {
    const pool = await poolPromise;

    // login z frontu traktujemy jako Email w dbo.Klienci
    const check = await pool
      .request()
      .input("email", sql.NVarChar(255), login)
      .query("SELECT TOP 1 UserID FROM dbo.Klienci WHERE Email = @email");

    if (check.recordset.length) {
      return res.status(409).json({ error: "Taki login już istnieje." });
    }

    const hash = bcrypt.hashSync(password, 10);

    // NOT NULL w dbo.Klienci: Email, PasswordHash, FirstName, LastName, IsActive, UserRole, CreatedDate
    await pool
      .request()
      .input("Email", sql.NVarChar(255), login)
      .input("PasswordHash", sql.NVarChar(255), hash)
      .input("FirstName", sql.NVarChar(100), "User")
      .input("LastName", sql.NVarChar(100), "User")
      .input("UserRole", sql.NVarChar(50), "user")
      .query(`
        INSERT INTO dbo.Klienci (Email, PasswordHash, FirstName, LastName, IsActive, UserRole, CreatedDate)
        VALUES (@Email, @PasswordHash, @FirstName, @LastName, 1, @UserRole, GETDATE())
      `);

    return res.status(201).json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: "DB error (register)", details: e.message });
  }
});


// logowanie
app.post("/api/auth/login", async (req, res) => {
  const { login, password } = req.body || {};
  if (!login || !password) return res.status(400).json({ error: "Brak danych" });

  try {
    const pool = await poolPromise;

    const r = await pool
      .request()
      .input("email", sql.NVarChar(255), login)
      .query(`
        SELECT TOP 1 UserID, Email, PasswordHash, IsActive
        FROM dbo.Klienci
        WHERE Email = @email
      `);

    if (!r.recordset.length) return res.status(401).json({ error: "Zły login lub hasło" });

    const user = r.recordset[0];

    const ok = bcrypt.compareSync(password, user.PasswordHash);
    if (!ok) return res.status(401).json({ error: "Zły login lub hasło" });

    req.session.user = { id: user.id, login: user.login };

req.session.save((err) => {
  if (err) return res.status(500).json({ error: "Session save error" });
  return res.json({ ok: true, user: { id: user.id, login: user.login } });
});

  } catch (e) {
    return res.status(500).json({ error: "DB error (login)", details: e.message });
  }
});


// kim jestem
app.get("/api/auth/me", (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: "Brak sesji" });
  res.json({ ok: true, user: req.session.user });
});

// wyloguj
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`Backend działa na http://localhost:${port}`));
