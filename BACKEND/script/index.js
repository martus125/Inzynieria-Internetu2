import express from "express";
import mysql from "mysql";
import bcrypt from "bcryptjs";
import session from "express-session";
import cookieParser from "cookie-parser";
import cors from "cors";

const app = express();

// === DB ===
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "123456789",
  database: "uzytkownicy", // schema w MySQL Workbench (patrz część 4)
});

// === Middlewares ===
app.use(cors({
  origin: [
    "http://localhost:5500",      // Live Server (VS Code)
    "http://127.0.0.1:5500",
    "http://localhost:3000",      // jeśli front z tego samego hosta
  ],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: "dev-secret-tylko-do-lokalu", // zmień w produkcji
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    // secure: true, // odkomentuj, gdy używasz HTTPS
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 dni
  },
}));

// === Helper: sprawdzanie sesji ===
function requireAuth(req, res, next) {
  if (req.session?.user) return next();
  return res.status(401).json({ error: "Nie zalogowano" });
}

// === API ===

// Healthcheck (opcjonalnie)
app.get("/", (req, res) => {
  res.json({ ok: true, msg: "Backend działa" });
});

// Rejestracja
app.post("/api/auth/register", (req, res) => {
  const { login, password } = req.body || {};
  if (!login || !password) return res.status(400).json({ error: "Podaj login i hasło" });
  if (password.length < 6) return res.status(400).json({ error: "Hasło min. 6 znaków" });

  // Sprawdź czy login zajęty
  db.query("SELECT id FROM uzytkownicy WHERE login = ?", [login], (err, rows) => {
    if (err) return res.status(500).json({ error: "Błąd bazy (sprawdzenie loginu)" });
    if (rows.length > 0) return res.status(409).json({ error: "Login zajęty" });

    const hash = bcrypt.hashSync(password, 10);
    db.query(
      "INSERT INTO uzytkownicy (login, password_hash) VALUES (?,?)",
      [login, hash],
      (err2, result) => {
        if (err2) return res.status(500).json({ error: "Błąd bazy (insert)" });
        res.status(201).json({ user: { id: result.insertId, login } });
      }
    );
  });
});

// Logowanie
app.post("/api/auth/login", (req, res) => {
  const { login, password } = req.body || {};
  if (!login || !password) return res.status(400).json({ error: "Podaj login i hasło" });

  db.query("SELECT id, login, password_hash FROM uzytkownicy WHERE login = ?", [login], (err, rows) => {
    if (err) return res.status(500).json({ error: "Błąd bazy (select)" });
    if (rows.length === 0) return res.status(401).json({ error: "Nieprawidłowe dane" });

    const user = rows[0];
    const ok = bcrypt.compareSync(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Nieprawidłowe dane" });

    req.session.user = { id: user.id, login: user.login };
    res.json({ user: req.session.user });
  });
});

// Wylogowanie
app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.status(204).end();
  });
});

// Kto zalogowany
app.get("/api/auth/me", (req, res) => {
  if (req.session?.user) return res.json({ user: req.session.user });
  res.status(204).end();
});

// (Opcjonalnie) endpoint tylko dla zalogowanych:
app.get("/api/booking/hello", requireAuth, (req, res) => {
  res.json({ msg: `Cześć ${req.session.user.login}, tu strefa zalogowanych!` });
});

// Start
app.listen(3000, () => {
  console.log("Backend działa na http://localhost:3000");
});
