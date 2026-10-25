import request from "supertest";
import { app } from "../src/app.js";
import { query, pool } from "../src/config/db.js";
import fs from "fs";

describe("TrustVault Security Boundary & Access Control Tests", () => {
  let ownerToken: string;
  let viewerToken: string;
  let testDocId: string;
  let testShareId: string;

  beforeAll(async () => {
    const ownerRes = await request(app)
      .post("/api/auth/login")
      .send({ email: "owner@vault.local", password: "Owner@123" });
    ownerToken = ownerRes.body.token;

    const viewerRes = await request(app)
      .post("/api/auth/login")
      .send({ email: "viewer@vault.local", password: "Viewer@123" });
    viewerToken = viewerRes.body.token;

    const uploadRes = await request(app)
      .post("/api/documents")
      .set("Authorization", `Bearer ${ownerToken}`)
      .field("title", "Confidential Quarterly Report")
      .field("category", "Finance")
      .attach("file", Buffer.from("%PDF-1.4 Mock Encrypted Document Stream"), "report.pdf");

    testDocId = uploadRes.body.id;
  });

  afterAll(async () => {
    if (testDocId) {
      await query("DELETE FROM document_shares WHERE document_id = ?", [testDocId]);
      await query("DELETE FROM documents WHERE id = ?", [testDocId]);
    }
    if (pool && typeof pool.end === "function") {
      await pool.end();
    }
  });

  test("RULE 1: Unauthorized user CANNOT access unshared document", async () => {
    const res = await request(app)
      .get(`/api/documents/${testDocId}/download`)
      .set("Authorization", `Bearer ${viewerToken}`);

    expect([403, 404]).toContain(res.status);
    expect(res.body.error).toBeDefined();
  });

  test("RULE 2: Revoking access immediately prevents file decryption", async () => {
    const shareRes = await request(app)
      .post(`/api/documents/${testDocId}/share`)
      .set("Authorization", `Bearer ${ownerToken}`)
      .send({
        recipientEmail: "viewer@vault.local",
        permission: "VIEW",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      });

    testShareId = shareRes.body.shareId;

    const activeRes = await request(app)
      .get(`/api/documents/${testDocId}/download`)
      .set("Authorization", `Bearer ${viewerToken}`);
    expect(activeRes.status).toBe(200);

    await request(app)
      .delete(`/api/documents/${testDocId}/share/${testShareId}`)
      .set("Authorization", `Bearer ${ownerToken}`);

    const revokedRes = await request(app)
      .get(`/api/documents/${testDocId}/download`)
      .set("Authorization", `Bearer ${viewerToken}`);
    expect([403, 404]).toContain(revokedRes.status);
  });

  test("RULE 3: Storage cipher modification triggers GCM tag integrity failure", async () => {
    const rows = await query<any>("SELECT storage_path FROM documents WHERE id = ?", [testDocId]);
    const filePath = rows[0].storage_path;

    const originalCiphertext = fs.readFileSync(filePath);

    // Corrupt one byte of the AES-256-GCM ciphertext on disk
    const corrupted = Buffer.from(originalCiphertext);
    corrupted[corrupted.length - 1] = corrupted[corrupted.length - 1] ^ 0xff;
    fs.writeFileSync(filePath, corrupted);

    let failedAsExpected = false;
    try {
      const tamperRes = await request(app)
        .get(`/api/documents/${testDocId}/download`)
        .set("Authorization", `Bearer ${ownerToken}`);

      if (tamperRes.status === 400 || (tamperRes.body.error && tamperRes.body.error.includes("integrity"))) {
        failedAsExpected = true;
      }
    } catch (err: any) {
      // Aborted stream indicates Node's GCM decipher destroyed the connection upon tag mismatch
      if (err.message && (err.message.includes("aborted") || err.code === "ECONNRESET")) {
        failedAsExpected = true;
      }
    }

    // Verify tamper alert was recorded in audit log
    const auditEntries = await query<any>(
      "SELECT * FROM audit_logs WHERE action = 'DOCUMENT_TAMPER_DETECTED' AND resource_id = ?",
      [testDocId]
    );

    if (auditEntries.length > 0) {
      failedAsExpected = true;
    }

    // Restore original file
    fs.writeFileSync(filePath, originalCiphertext);

    expect(failedAsExpected).toBe(true);
  });
});
