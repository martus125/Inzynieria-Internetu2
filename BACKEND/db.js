import sql from "mssql";
import dotenv from "dotenv";

// twardo wskazujemy .env w tym samym folderze co db.js
dotenv.config({ path: new URL("./.env", import.meta.url) });

console.log("ENV CHECK:", {
  DB_SERVER: process.env.DB_SERVER,
  DB_DATABASE: process.env.DB_DATABASE,
  DB_USER: process.env.DB_USER ? "***ok***" : undefined,
});

const config = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,         // <- tu ma być string
  database: process.env.DB_DATABASE,
  port: Number(process.env.DB_PORT || 1433),
  options: {
    encrypt: true,
    trustServerCertificate: false,
  },
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 },
};

export const poolPromise = new sql.ConnectionPool(config)
  .connect()
  .then((pool) => {
    console.log("✅ Połączono z Azure SQL");
    return pool;
  })
  .catch((err) => {
    console.error("❌ Błąd połączenia z Azure SQL:", err);
    throw err;
  });

export { sql };
