const express = require("express");
const databaseManager = require("../config/database");
const { log } = require("../services/totpService");

const router = express.Router();

router.post("/list", async (req, res) => {
  try {
    const { username } = req.body;
    if (!username) return res.status(400).json({ success: false, message: "Username required" });

    const rows = await databaseManager.query(
      "SELECT SessionToken, UserLogin, LastUsedTS, SessionInfo FROM appblddbo.TwoFactorSession WHERE UserLogin = ?",
      [username]
    );

    const sessions = rows.map((row) => {
      let info = {};
      try { info = JSON.parse(row.SessionInfo); } catch {}
      return {
        sessionToken: row.SessionToken,
        username: row.UserLogin,
        lastUsed: row.LastUsedTS,
        loginTime: info.loginTime || null,
        deviceInfo: info.deviceInfo || null,
        ipAddress: info.ipAddress || null,
        requires2FA: info.requires2FA || false,
        authenticated2FA: info.sessionType === "authenticated" || info.authenticated2FA === true,
        sessionType: info.sessionType || "unknown",
      };
    });

    res.json({ success: true, sessions, timestamp: new Date().toISOString() });
  } catch (error) {
    log("ERROR", "Sessions list error", { error: error.message });
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

router.post("/logout", async (req, res) => {
  try {
    const { username, sessionToken } = req.body;
    if (!username || !sessionToken) {
      return res.status(400).json({ success: false, message: "Username and sessionToken required" });
    }
    await databaseManager.query(
      "DELETE FROM appblddbo.TwoFactorSession WHERE SessionToken = ? AND UserLogin = ?",
      [sessionToken, username]
    );
    log("INFO", `Session logged out for ${username}`);
    res.json({ success: true, message: "Session terminated", timestamp: new Date().toISOString() });
  } catch (error) {
    log("ERROR", "Session logout error", { error: error.message });
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

router.post("/logout-all", async (req, res) => {
  try {
    const { username, keepSessionToken } = req.body;
    if (!username) return res.status(400).json({ success: false, message: "Username required" });

    if (keepSessionToken) {
      await databaseManager.query(
        "DELETE FROM appblddbo.TwoFactorSession WHERE UserLogin = ? AND SessionToken != ?",
        [username, keepSessionToken]
      );
    } else {
      await databaseManager.query("DELETE FROM appblddbo.TwoFactorSession WHERE UserLogin = ?", [username]);
    }

    log("INFO", `All other sessions logged out for ${username}`);
    res.json({ success: true, message: "Other sessions terminated", timestamp: new Date().toISOString() });
  } catch (error) {
    log("ERROR", "Sessions logout-all error", { error: error.message });
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

module.exports = router;
