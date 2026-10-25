import {
  shareDocument,
  getSharedWithMe,
  revokeShare,
  getDocumentShares
} from "./controllers/share.controller.js";
import express from "express";
import fs from "fs";
import path from "path";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { login, register } from "./controllers/auth.controller.js";
import {
  uploadDocument,
  listDocuments,
  downloadDocument,
  deleteDocument,
  updateDocument
} from "./controllers/document.controller.js";
import { authenticate } from "./middleware/auth.middleware.js";
import { uploadMemory, validateUploadedFile } from "./middleware/upload.middleware.js";
import auditRoutes from "./routes/audit.routes.js";
import adminRoutes from "./routes/admin.routes.js";

export const app = express();

// ─── Security Headers ────────────────────────────────────────────────────────
app.use(helmet());

// ─── CORS: locked to configured frontend origin ───────────────────────────────
const allowedOrigin = process.env.FRONTEND_ORIGIN || "http://localhost:5173";
app.use(
  cors({
    origin: allowedOrigin,
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());

// ─── Rate Limiters ───────────────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts. Please try again after 15 minutes." },
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Upload rate limit exceeded." },
});

// ─── Public Routes ───────────────────────────────────────────────────────────
app.get("/api/health", (_req, res) => {
  res.json({ status: "OK", timestamp: new Date().toISOString() });
});

app.post("/api/auth/login", loginLimiter, login);
app.post("/api/auth/register", register);

// ─── Authenticated Document Operations ───────────────────────────────────────
// NOTE: /shared-with-me MUST be registered before /:id routes to avoid Express
// matching "shared-with-me" as a document ID parameter.
app.get("/api/documents/shared-with-me", authenticate, getSharedWithMe);

app.get("/api/documents", authenticate, listDocuments);
app.post(
  "/api/documents",
  authenticate,
  uploadLimiter,
  uploadMemory.single("file"),
  validateUploadedFile,
  uploadDocument
);

app.get("/api/documents/:id/download", authenticate, downloadDocument);
app.patch("/api/documents/:id", authenticate, updateDocument);
app.delete("/api/documents/:id", authenticate, deleteDocument);

// ─── Share Management ─────────────────────────────────────────────────────────
app.post("/api/documents/:id/share", authenticate, shareDocument);
app.get("/api/documents/:id/shares", authenticate, getDocumentShares);
app.delete("/api/documents/:id/share/:shareId", authenticate, revokeShare);

// ─── Audit & Admin ───────────────────────────────────────────────────────────
app.use("/api/audit", auditRoutes);
app.use("/api/admin", adminRoutes);

// ─── Hosted frontend (single origin deploy) ──────────────────────────────────
// When STATIC_DIR points at a Vite build, Express serves it so the site and the
// API share one URL and the relative "/api" calls keep working without CORS.
const staticDir = process.env.STATIC_DIR;
if (staticDir && fs.existsSync(staticDir)) {
  app.use(express.static(staticDir));
  app.get(/^(?!\/api\/).*/, (_req, res) => {
    res.sendFile(path.join(staticDir, "index.html"));
  });
}