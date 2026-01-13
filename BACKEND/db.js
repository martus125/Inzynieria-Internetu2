import sql from "mssql";
import dotenv from "dotenv";

// ładujemy .env z folderu BACKEND
dotenv.config();

console.log("ENV CHECK:", {
  DB_SERVER: process.env.DB_SERVER,
  DB_DATABASE: process.env.DB_DATABASE,
  DB_USER: process.env.DB_USER ? "***ok***" : undefined,
});

const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE,
  port: Number(process.env.DB_PORT || 1433),
  options: {
    encrypt: true,
    trustServerCertificate: false,
  },
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 },
};

const pool = new sql.ConnectionPool(config);

export const poolPromise = pool
  .connect()
  .then((p) => {
    console.log("✅ Połączono z Azure SQL");
    return p;
  })
  .catch((err) => {
    console.error("❌ Błąd połączenia z Azure SQL:", err);
    throw err;
  });

export { sql };
