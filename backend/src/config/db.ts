import mysql from "mysql2/promise";
import dotenv from "dotenv";

dotenv.config();

// Managed hosts (Railway, Render, ...) inject a single connection string; local dev uses DB_* vars.
export const pool = process.env.DATABASE_URL
  ? mysql.createPool(process.env.DATABASE_URL)
  : mysql.createPool({
      host: process.env.DB_HOST || "localhost",
      port: parseInt(process.env.DB_PORT || "3306", 10),
      user: process.env.DB_USER || "root",
      password: process.env.DB_PASSWORD || "",
      database: process.env.DB_NAME || "trustvault_db",
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });

export async function query<T = any>(sql: string, params: any[] = []): Promise<T[]> {
  const [rows] = await pool.execute(sql, params);
  return rows as T[];
}
