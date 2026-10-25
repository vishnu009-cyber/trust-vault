import { Request, Response } from "express";
import path from "path";
import fs from "fs";
import crypto from "crypto";
import { Readable } from "stream";
import { query } from "../config/db.js";
import { CryptoService } from "../services/crypto.service.js";
import { AuditService } from "../services/audit.service.js";

const STORAGE_DIR = process.env.STORAGE_DIR
  ? path.resolve(process.env.STORAGE_DIR)
  : path.resolve(process.cwd(), "storage/encrypted");

if (!fs.existsSync(STORAGE_DIR)) {
  fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

// Magic byte verification for secure upload validation
function isValidFileType(buffer: Buffer, originalFilename: string): boolean {
  const blockedExtensions = [".exe", ".bat", ".cmd", ".sh", ".php", ".js", ".vbs", ".ps1"];
  const ext = path.extname(originalFilename).toLowerCase();
  if (blockedExtensions.includes(ext)) {
    return false;
  }

  if (buffer.length < 4) return false;

  const isPdf = buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46; // %PDF
  const isPng = buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47; // .PNG
  const isJpg = buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF;                       // JPEG
  const isZipOrDocx = buffer[0] === 0x50 && buffer[1] === 0x4B;                                       // PK (ZIP/DOCX/XLSX)
  const isText = buffer.slice(0, 512).every(
    byte => byte === 0x09 || byte === 0x0A || byte === 0x0D || (byte >= 0x20 && byte <= 0x7E)
  );

  return isPdf || isPng || isJpg || isZipOrDocx || isText;
}

// ─── Upload ──────────────────────────────────────────────────────────────────
export async function uploadDocument(req: Request, res: Response): Promise<void> {
  const userId = (req as any).user?.id;
  const ip = req.ip || req.socket.remoteAddress || "unknown";

  if (!req.file || !req.file.buffer) {
    res.status(400).json({ error: "File payload is required." });
    return;
  }

  // 1. Enforce hard size limit (25MB)
  if (req.file.size > 25 * 1024 * 1024) {
    res.status(413).json({ error: "File exceeds maximum permissible size of 25MB." });
    return;
  }

  // 2. Validate binary signature / magic bytes
  if (!isValidFileType(req.file.buffer, req.file.originalname)) {
    await AuditService.record({
      actorId: userId,
      action: "SUSPICIOUS_UPLOAD_BLOCKED",
      ipAddress: ip,
      status: "DENIED",
      metadata: { filename: req.file.originalname, size: req.file.size }
    });
    res.status(400).json({ error: "File validation failed: Executable or unrecognized format rejected." });
    return;
  }

  const { title, category, description } = req.body || {};
  if (!title || !category) {
    res.status(400).json({ error: "Title and category are required." });
    return;
  }

  const documentId = crypto.randomUUID();
  const encryptedStorageFileName = `${documentId}.enc`;
  const targetStoragePath = path.join(STORAGE_DIR, encryptedStorageFileName);

  try {
    // 3. Calculate SHA-256 integrity hash from the buffer
    const sha256 = crypto.createHash("sha256").update(req.file.buffer).digest("hex");

    // 4. Stream and encrypt in-memory buffer directly to disk (AES-256-GCM)
    const inputStream = Readable.from(req.file.buffer);
    const { ivHex, authTagHex } = await CryptoService.encryptFileStream(inputStream, targetStoragePath);

    // 5. Persist metadata into documents table
    await query(
      `INSERT INTO documents 
        (id, owner_id, title, category, description, storage_path, original_filename, mime_type, file_size_bytes, sha256_checksum, iv, auth_tag, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        documentId,
        userId,
        title,
        category,
        description || null,
        targetStoragePath,
        req.file.originalname,
        req.file.mimetype,
        req.file.size,
        sha256,
        ivHex,
        authTagHex,
      ]
    );

    // 6. Audit log — includes actorId so the trail knows who uploaded
    await AuditService.record({
      actorId: userId,
      action: "DOCUMENT_UPLOADED",
      resourceId: documentId,
      ipAddress: ip,
      status: "SUCCESS",
      metadata: { documentId, filename: req.file.originalname, sha256 },
    });

    res.status(201).json({
      id: documentId,
      title,
      category,
      originalFilename: req.file.originalname,
      fileSizeBytes: req.file.size,
      checksum: sha256,
    });
  } catch (error) {
    if (fs.existsSync(targetStoragePath)) {
      fs.unlinkSync(targetStoragePath);
    }
    res.status(500).json({ error: "Document encryption failed." });
  }
}

// ─── Download ────────────────────────────────────────────────────────────────
export async function downloadDocument(req: Request, res: Response): Promise<void> {
  const documentId = req.params.id;
  const userId = (req as any).user?.id;
  const ip = req.ip || req.socket.remoteAddress || "unknown";

  try {
    // Single atomic database authorization check — the server decides every time
    const docs = await query<any>(
      `SELECT d.*, 
              ds.id AS share_id, ds.permission, ds.expires_at, ds.max_downloads, ds.download_count
       FROM documents d
       LEFT JOIN document_shares ds 
         ON d.id = ds.document_id 
         AND ds.shared_with_user_id = ?
         AND (ds.expires_at IS NULL OR ds.expires_at > NOW())
       WHERE d.id = ? 
         AND d.is_deleted = 0 
         AND (d.owner_id = ? OR ds.id IS NOT NULL)`,
      [userId, documentId, userId]
    );

    if (docs.length === 0) {
      await AuditService.record({
        actorId: userId,
        action: "DOCUMENT_DOWNLOAD_DENIED",
        resourceId: documentId,
        ipAddress: ip,
        status: "DENIED",
        metadata: { attemptedDocumentId: documentId },
      });
      res.status(404).json({ error: "Document not found or access denied." });
      return;
    }

    const doc = docs[0];

    // Check download quota if accessed through delegation
    if (doc.owner_id !== userId && doc.share_id) {
      if (doc.permission === "DOWNLOAD") {
        if (doc.max_downloads !== null && doc.download_count >= doc.max_downloads) {
          res.status(403).json({ error: "Download limit reached for this document." });
          return;
        }

        // Increment count only for valid DOWNLOAD permits
        await query(
          "UPDATE document_shares SET download_count = download_count + 1 WHERE id = ?",
          [doc.share_id]
        );
      }
    }

    if (!fs.existsSync(doc.storage_path)) {
      res.status(500).json({ error: "Encrypted file missing from storage." });
      return;
    }

    // Set presentation headers: inline for VIEW sessions, attachment for DOWNLOAD
    const isViewOnly = doc.owner_id !== userId && doc.permission === "VIEW";
    const dispositionType = isViewOnly ? "inline" : "attachment";

    try {
      res.setHeader("Content-Type", doc.mime_type || "application/octet-stream");
      res.setHeader(
        "Content-Disposition",
        `${dispositionType}; filename="${encodeURIComponent(doc.original_filename)}"`
      );

      await CryptoService.decryptFileStream(
        doc.storage_path,
        doc.iv,
        doc.auth_tag,
        res
      );

      await AuditService.record({
        actorId: userId,
        action: isViewOnly ? "DOCUMENT_VIEWED" : "DOCUMENT_DOWNLOADED",
        resourceId: documentId,
        ipAddress: ip,
        status: "SUCCESS",
        metadata: { documentId },
      });
    } catch (cryptoErr: any) {
      await AuditService.record({
        actorId: userId,
        action: "DOCUMENT_TAMPER_DETECTED",
        resourceId: documentId,
        ipAddress: ip,
        status: "DENIED",
        metadata: { documentId, details: "GCM auth tag verification failed." },
      });

      if (!res.headersSent) {
        res.status(400).json({ error: "Cryptographic integrity check failed. Document corrupted or tampered." });
      } else {
        res.destroy(new Error("Cryptographic integrity check failed."));
      }
      return;
    }
  } catch (error) {
    if (!res.headersSent) {
      res.status(500).json({ error: "Stream decryption failed." });
    }
  }
}

// ─── List (with search) ──────────────────────────────────────────────────────
export async function listDocuments(req: Request, res: Response): Promise<void> {
  const userId = (req as any).user?.id;
  const userRole = (req as any).user?.role;
  const { search, category, startDate, endDate, owner } = req.query;

  try {
    let sql = `SELECT d.id, d.title, d.category, d.description, d.original_filename, 
                      d.mime_type, d.file_size_bytes, d.sha256_checksum, d.created_at,
                      u.email AS owner_email
               FROM documents d
               JOIN users u ON d.owner_id = u.id
               WHERE d.is_deleted = 0`;
    const params: any[] = [];

    // Admins can see all docs; others only see their own
    if (userRole !== "ADMIN") {
      sql += ` AND d.owner_id = ?`;
      params.push(userId);
    }

    if (search) {
      sql += ` AND (d.title LIKE ? OR d.original_filename LIKE ?)`;
      params.push(`%${search}%`, `%${search}%`);
    }
    if (category) {
      sql += ` AND d.category = ?`;
      params.push(category);
    }
    // Admin-only: filter by owner email
    if (owner && userRole === "ADMIN") {
      sql += ` AND u.email LIKE ?`;
      params.push(`%${owner}%`);
    }
    if (startDate) {
      sql += ` AND d.created_at >= ?`;
      params.push(startDate);
    }
    if (endDate) {
      sql += ` AND d.created_at <= ?`;
      params.push(endDate);
    }

    sql += ` ORDER BY d.created_at DESC`;

    const docs = await query<any>(sql, params);
    res.json({ documents: docs });
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch documents." });
  }
}

// ─── Soft Delete ─────────────────────────────────────────────────────────────
export async function deleteDocument(req: Request, res: Response): Promise<void> {
  const documentId = req.params.id;
  const userId = (req as any).user?.id;
  const userRole = (req as any).user?.role;
  const ip = req.ip || req.socket.remoteAddress || "unknown";

  try {
    // Server enforces ownership — user can only delete their own docs;
    // ADMIN can delete any document
    const whereClause = userRole === "ADMIN"
      ? `WHERE id = ? AND is_deleted = 0`
      : `WHERE id = ? AND owner_id = ? AND is_deleted = 0`;
    const whereParams = userRole === "ADMIN" ? [documentId] : [documentId, userId];

    const docs = await query<any>(
      `SELECT id, title FROM documents ${whereClause}`,
      whereParams
    );

    if (docs.length === 0) {
      await AuditService.record({
        actorId: userId,
        action: "DOCUMENT_DELETE_DENIED",
        resourceId: documentId,
        ipAddress: ip,
        status: "DENIED",
        metadata: { attemptedDocumentId: documentId },
      });
      res.status(404).json({ error: "Document not found or access denied." });
      return;
    }

    // Soft delete — preserves audit trail linkage
    await query(`UPDATE documents SET is_deleted = 1 WHERE id = ?`, [documentId]);

    await AuditService.record({
      actorId: userId,
      action: "DOCUMENT_DELETED",
      resourceId: documentId,
      ipAddress: ip,
      status: "SUCCESS",
      metadata: { documentTitle: docs[0].title },
    });

    res.json({ message: "Document deleted successfully." });
  } catch (error) {
    res.status(500).json({ error: "Failed to delete document." });
  }
}

// ─── Update Metadata ─────────────────────────────────────────────────────────
export async function updateDocument(req: Request, res: Response): Promise<void> {
  const documentId = req.params.id;
  const userId = (req as any).user?.id;
  const ip = req.ip || req.socket.remoteAddress || "unknown";
  const { title, category, description } = req.body || {};

  if (!title && !category && !description) {
    res.status(400).json({ error: "At least one field (title, category, description) must be provided." });
    return;
  }

  try {
    // CRITICAL: AND owner_id = ? ensures only the owner can update — server enforces this
    const docs = await query<any>(
      `SELECT id FROM documents WHERE id = ? AND owner_id = ? AND is_deleted = 0`,
      [documentId, userId]
    );

    if (docs.length === 0) {
      await AuditService.record({
        actorId: userId,
        action: "DOCUMENT_UPDATE_DENIED",
        resourceId: documentId,
        ipAddress: ip,
        status: "DENIED",
        metadata: { attemptedDocumentId: documentId },
      });
      res.status(404).json({ error: "Document not found or access denied." });
      return;
    }

    const updates: string[] = [];
    const params: any[] = [];

    if (title) { updates.push("title = ?"); params.push(title); }
    if (category) { updates.push("category = ?"); params.push(category); }
    if (description !== undefined) { updates.push("description = ?"); params.push(description); }

    params.push(documentId);
    await query(`UPDATE documents SET ${updates.join(", ")} WHERE id = ?`, params);

    await AuditService.record({
      actorId: userId,
      action: "DOCUMENT_UPDATED",
      resourceId: documentId,
      ipAddress: ip,
      status: "SUCCESS",
      metadata: { updatedFields: Object.keys({ title, category, description }).filter(k => req.body[k]) },
    });

    res.json({ message: "Document metadata updated successfully." });
  } catch (error) {
    res.status(500).json({ error: "Failed to update document." });
  }
}

