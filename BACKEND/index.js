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

// statyczny frontend
app.use(express.static(path.join(__dirname, "..", "FRONTED")));

// statyczne obrazki (pewny adres /images/...)
app.use("/images", express.static(path.join(__dirname, "..", "FRONTED", "images")));



// JSON + cookies
app.use(express.json());
app.use(cookieParser());

// CORS (bez app.options("*") bo w Express 5 potrafi wywalać błąd)
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
// preflight na każdą ścieżkę (bez gwiazdki)
app.options(/.*/, cors({ origin: true, credentials: true }));

// SESJA (TYLKO RAZ)
app.use(
  session({
    name: "olimp.sid",
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false, // dev bez https
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

/* =========================
   HELPERS
========================= */
function requireAuth(req, res, next) {
  if (!req.session?.user) return res.status(401).json({ error: "Zaloguj się, aby rezerwować." });
  next();
}

function isISODate(s) {
  return typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s);
}
function startOfTodayLocal() {
  const now = new Date();
  return new Date(now.getFullYear(), now.getMonth(), now.getDate()); // 00:00 lokalnie
}

/* =========================
   HEALTH
========================= */
app.get("/api/ping", (req, res) => res.json({ ok: true, msg: "Backend działa" }));

app.get("/api/health", async (req, res) => {
  try {
    const pool = await poolPromise;
    const r = await pool.request().query("SELECT 1 AS result");
    res.json({ status: "ok", db: r.recordset[0].result });
  } catch (e) {
    res.status(500).json({ status: "error", error: e.message });
  }
});

/* =========================
   AUTH
========================= */

// rejestracja
app.post("/api/auth/register", async (req, res) => {
  const { login, password } = req.body || {};
  if (!login || !password || password.length < 6) {
    return res.status(400).json({ error: "Podaj login i hasło (min. 6 znaków)." });
  }

  try {
    const pool = await poolPromise;

    const check = await pool
      .request()
      .input("email", sql.NVarChar(255), login)
      .query("SELECT TOP 1 UserID FROM dbo.Klienci WHERE Email = @email");

    if (check.recordset.length) {
      return res.status(409).json({ error: "Taki login już istnieje." });
    }

    const hash = bcrypt.hashSync(password, 10);

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
    if (user.IsActive === 0) return res.status(403).json({ error: "Konto nieaktywne." });

    const ok = bcrypt.compareSync(password, user.PasswordHash);
    if (!ok) return res.status(401).json({ error: "Zły login lub hasło" });

    // ✅ poprawnie zapisujemy sesję
    req.session.user = { id: user.UserID, login: user.Email };

    req.session.save((err) => {
      if (err) return res.status(500).json({ error: "Session save error" });
      return res.json({ ok: true, user: req.session.user });
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

/* =========================
   ROOMS: SEARCH + BOOK + MY
========================= */

// Szukanie dostępności po typie (from/to/guests)
app.get("/api/rooms/search", async (req, res) => {
  const { from, to, guests } = req.query;

  if (!isISODate(from) || !isISODate(to)) {
    return res.status(400).json({ error: "Podaj daty YYYY-MM-DD (from, to)." });
  }

  const g = Number(guests || 1);
  if (!Number.isFinite(g) || g < 1) return res.status(400).json({ error: "Niepoprawna liczba gości." });

  const dateFrom = new Date(from + "T00:00:00");
  const dateTo = new Date(to + "T00:00:00");
  const today = startOfTodayLocal();
if (dateFrom < today) {
  return res.status(400).json({ error: "Nie można wyszukiwać pokoi w przeszłości. Wybierz dzisiejszą lub przyszłą datę." });
}

  if (!(dateTo > dateFrom)) return res.status(400).json({ error: "Data 'to' musi być po 'from'." });

  try {
    const pool = await poolPromise;

    const q = await pool
      .request()
      .input("DataOd", sql.Date, dateFrom)
      .input("DataDo", sql.Date, dateTo)
      .input("Guests", sql.Int, g)
      .query(`
        SELECT
          p.TypPokoju,
          MIN(p.CenaZaNoc) AS CenaOd,
          MAX(p.MaxOsob) AS MaxOsob,
          MIN(p.Opis) AS Opis,
          COUNT(*) AS Wszystkie,
          SUM(CASE WHEN ov.HasOverlap IS NULL THEN 1 ELSE 0 END) AS Dostepne
        FROM dbo.Pokoje p
        OUTER APPLY (
          SELECT TOP 1 1 AS HasOverlap
          FROM dbo.RezerwacjeNoclegow r
          WHERE r.PokojID = p.PokojID
            AND r.StatusRezerwacji IN ('PENDING','CONFIRMED')
            AND r.DataZameldowania < @DataDo
            AND r.DataWymeldowania > @DataOd
        ) ov
        WHERE p.CzyAktywny = 1
          AND p.MaxOsob >= @Guests
        GROUP BY p.TypPokoju
        ORDER BY MIN(p.CenaZaNoc) ASC;
      `);

    res.json({ ok: true, items: q.recordset });
  } catch (e) {
    res.status(500).json({ error: "DB error (rooms/search)", details: e.message });
  }
});

// Rezerwacja 1 wolnego pokoju danego typu (blokada terminów)
app.post("/api/rooms/book", requireAuth, async (req, res) => {
  const { roomType, from, to, guests, children, firstName, lastName, phone, notes } = req.body || {};

  if (!roomType) return res.status(400).json({ error: "Brak roomType." });
  if (!isISODate(from) || !isISODate(to)) return res.status(400).json({ error: "Daty muszą być YYYY-MM-DD." });

  const adults = Number(guests || 1);
  const kids = Number(children || 0);
  if (!Number.isFinite(adults) || adults < 1) return res.status(400).json({ error: "Niepoprawna liczba dorosłych." });
  if (!Number.isFinite(kids) || kids < 0) return res.status(400).json({ error: "Niepoprawna liczba dzieci." });

  const fn = String(firstName || "").trim();
  const ln = String(lastName || "").trim();
  const ph = String(phone || "").trim();
  const nt = String(notes || "").trim();

  if (fn.length < 2 || ln.length < 2) return res.status(400).json({ error: "Podaj imię i nazwisko." });
  if (ph.length && ph.length < 7) return res.status(400).json({ error: "Telefon wygląda na zbyt krótki." });
  if (nt.length > 400) return res.status(400).json({ error: "Uwagi max 400 znaków." });

  const totalGuests = adults + kids;

  const dateFrom = new Date(from + "T00:00:00");
  const dateTo = new Date(to + "T00:00:00");
  const today = startOfTodayLocal();
if (dateFrom < today) {
  return res.status(400).json({ error: "Nie można rezerwować pokoju w przeszłości." });
}

  if (!(dateTo > dateFrom)) return res.status(400).json({ error: "Data 'to' musi być po 'from'." });

  const nights = Math.round((dateTo - dateFrom) / (1000 * 60 * 60 * 24));
  if (nights < 1) return res.status(400).json({ error: "Minimalnie 1 noc." });

  let tx;

  try {
    const pool = await poolPromise;
    tx = new sql.Transaction(pool);

    await tx.begin(sql.ISOLATION_LEVEL.SERIALIZABLE);
    const rq = new sql.Request(tx);

    rq.input("TypPokoju", sql.NVarChar(100), roomType);
    rq.input("DataOd", sql.Date, dateFrom);
    rq.input("DataDo", sql.Date, dateTo);
    rq.input("Guests", sql.Int, totalGuests);

    // 1) wybierz 1 wolny pokój i zablokuj transakcyjnie
    const pick = await rq.query(`
      SELECT TOP 1 p.PokojID, p.CenaZaNoc, p.MaxOsob
      FROM dbo.Pokoje p WITH (UPDLOCK, HOLDLOCK)
      WHERE p.CzyAktywny = 1
        AND p.TypPokoju = @TypPokoju
        AND p.MaxOsob >= @Guests
        AND NOT EXISTS (
          SELECT 1
          FROM dbo.RezerwacjeNoclegow r WITH (UPDLOCK, HOLDLOCK)
          WHERE r.PokojID = p.PokojID
            AND r.StatusRezerwacji IN ('PENDING','CONFIRMED')
            AND r.DataZameldowania < @DataDo
            AND r.DataWymeldowania > @DataOd
        )
      ORDER BY p.CenaZaNoc ASC, p.PokojID ASC;
    `);

    if (!pick.recordset.length) {
      await tx.rollback();
      return res.status(409).json({ error: "Brak wolnych pokoi w tym terminie." });
    }

    const room = pick.recordset[0];
    const total = Number(room.CenaZaNoc) * nights;

    rq.input("UserID", sql.Int, req.session.user.id);
    rq.input("PokojID", sql.Int, room.PokojID);
    rq.input("Dorosli", sql.Int, adults);
    rq.input("Dzieci", sql.Int, kids);
    rq.input("CenaCalkowita", sql.Decimal(10, 2), total);

    rq.input("Imie", sql.NVarChar(100), fn);
    rq.input("Nazwisko", sql.NVarChar(100), ln);
    rq.input("Telefon", sql.NVarChar(30), ph);
    rq.input("Uwagi", sql.NVarChar(400), nt);

    // 2) zaktualizuj dane klienta (żeby nie było "User User")
    await rq.query(`
      UPDATE dbo.Klienci
      SET FirstName = @Imie, LastName = @Nazwisko
      WHERE UserID = @UserID;
    `);

    // 3) insert rezerwacji do TWOJEJ tabeli + nowe pola
    const ins = await rq.query(`
      INSERT INTO dbo.RezerwacjeNoclegow
        (UserID, PokojID, DataZameldowania, DataWymeldowania,
         LiczbaOsobDoroslych, LiczbaDzieci, CenaCalkowita,
         StatusRezerwacji, DataUtworzenia,
         Imie, Nazwisko, Telefon, Uwagi)
      OUTPUT INSERTED.RezerwacjaNocleguID
      VALUES
        (@UserID, @PokojID, @DataOd, @DataDo,
         @Dorosli, @Dzieci, @CenaCalkowita,
         'CONFIRMED', GETDATE(),
         @Imie, @Nazwisko, @Telefon, @Uwagi);
    `);

    await tx.commit();

    res.json({
      ok: true,
      reservationId: ins.recordset[0].RezerwacjaNocleguID,
      nights,
      total,
      pokojId: room.PokojID,
    });
  } catch (e) {
    try { if (tx) await tx.rollback(); } catch {}
    res.status(500).json({ error: "DB error (rooms/book)", details: e.message });
  }
});


// Moje rezerwacje
app.get("/api/rooms/my", requireAuth, async (req, res) => {
  try {
    const pool = await poolPromise;
    const r = await pool
      .request()
      .input("UserID", sql.Int, req.session.user.id)
      .query(`
        SELECT TOP 50
          rn.RezerwacjaNocleguID AS RezerwacjaID,
          rn.DataZameldowania AS DataOd,
          rn.DataWymeldowania AS DataDo,
          rn.LiczbaOsobDoroslych AS Dorosli,
          rn.LiczbaDzieci AS Dzieci,
          rn.CenaCalkowita AS CenaCalkowita,
          rn.StatusRezerwacji AS Status,
          p.TypPokoju,
          p.NumerPokoju
        FROM dbo.RezerwacjeNoclegow rn
        JOIN dbo.Pokoje p ON p.PokojID = rn.PokojID
        WHERE rn.UserID = @UserID
        ORDER BY rn.DataUtworzenia DESC;
      `);

    res.json({ ok: true, items: r.recordset });
  } catch (e) {
    res.status(500).json({ error: "DB error (rooms/my)", details: e.message });
  }
});

/* =========================
   START
========================= */
const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`Backend działa na http://localhost:${port}`));
