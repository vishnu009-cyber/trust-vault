import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

// Managed MySQL providers (TiDB Cloud, PlanetScale, Aiven) require TLS on the public endpoint.
function tlsOptions(): mysql.SslOptions | undefined {
  if ((process.env.DB_SSL || "").toLowerCase() !== "true") return undefined;
  return {
    rejectUnauthorized:
      (process.env.DB_SSL_REJECT_UNAUTHORIZED || "true").toLowerCase() !== "false",
  };
}

// mysql2 accepts (uri, options) at runtime but its typings declare one argument.
const createPoolFromUri = mysql.createPool as unknown as (
  uri: string,
  options?: { ssl?: mysql.SslOptions }
) => mysql.Pool;

// Managed hosts (Railway, Render, ...) inject a single connection string; local dev uses DB_* vars.
export const pool = process.env.DATABASE_URL
  ? createPoolFromUri(process.env.DATABASE_URL, { ssl: tlsOptions() })
  : mysql.createPool({
      host: process.env.DB_HOST || "localhost",
      port: parseInt(process.env.DB_PORT || "3306", 10),
      user: process.env.DB_USER || "root",
      password: process.env.DB_PASSWORD || "",
      database: process.env.DB_NAME || "trustvault_db",
      ssl: tlsOptions(),
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });

export async function query<T = any>(sql: string, params: any[] = []): Promise<T[]> {
  const [rows] = await pool.execute(sql, params);
  return rows as T[];
}
