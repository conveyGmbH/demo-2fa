const express = require("express");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const databaseManager = require("../../config/database");
const config = require("../../config/config");
const { log, detectDeviceFromUserAgent } = require("../../services/totpService");

const router = express.Router();

const oauthStates = new Map();

function generateOAuthState() {
  const state = crypto.randomBytes(16).toString("hex");
  oauthStates.set(state, Date.now());
  setTimeout(() => oauthStates.delete(state), 600000);
  return state;
}

function sendPopupResponse(res, frontendURL, data) {
  res.redirect(frontendURL + "?" + new URLSearchParams(data).toString());
}

router.get("/google", (req, res) => {
  if (!config.google?.clientId) {
    return res.status(503).json({ success: false, message: "Google OAuth not configured" });
  }
  const state = generateOAuthState();
  const params = new URLSearchParams({
    client_id: config.google.clientId,
    redirect_uri: config.google.callbackURL,
    response_type: "code",
    scope: "openid email profile",
    state,
    access_type: "online",
    prompt: "select_account",
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
});

router.get("/google/callback", async (req, res) => {
  const frontendURL = process.env.FRONTEND_URL || "http://localhost:3000";
  const { code, state, error } = req.query;

  if (error) return sendPopupResponse(res, frontendURL, { error });
  if (!state || !oauthStates.has(state)) {
    return sendPopupResponse(res, frontendURL, { error: "Invalid or expired OAuth state" });
  }
  oauthStates.delete(state);

  try {
    const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        client_id: config.google.clientId,
        client_secret: config.google.clientSecret,
        redirect_uri: config.google.callbackURL,
        grant_type: "authorization_code",
      }),
    });
    const tokens = await tokenRes.json();
    if (!tokens.id_token) throw new Error("Google token exchange failed");

    const infoRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${tokens.id_token}`);
    const payload = await infoRes.json();
    if (payload.error || !payload.email) throw new Error("Could not verify Google identity");

    const email = payload.email;
    log("INFO", `Google login attempt for: ${email}`);

    const mitarbeiterRows = await databaseManager.query(
      "SELECT * FROM appblddbo.Mitarbeiter WHERE \"Login\" = ?", [email]
    );
    if (!mitarbeiterRows.length) {
      return sendPopupResponse(res, frontendURL, { error: `No portal account found for ${email}` });
    }

    const loginName = email;
    const twoFactorRows = await databaseManager.query(
      "SELECT * FROM appblddbo.TwoFactorUser WHERE LoginName = ?", [loginName]
    );

    const deviceInfo = detectDeviceFromUserAgent(req.get("User-Agent"), "Web Browser");
    const sessionToken = uuidv4();
    let is2FAEnabled = false;
    let userIdInt = null;

    if (twoFactorRows.length) {
      userIdInt = parseInt(twoFactorRows[0].TwoFactorUserID);
      const deviceQuery = await databaseManager.query(
        "SELECT COUNT(*) as count FROM appblddbo.TwoFactorDevice WHERE Inactive IS NULL AND TwoFactorUserID = ?",
        [userIdInt]
      );
      is2FAEnabled = !twoFactorRows[0].Disable2FA && deviceQuery[0].count > 0;
    }

    if (is2FAEnabled) {
      const sessionData = {
        username: loginName, userId: userIdInt, originalPassword: null,
        loginTime: new Date().toISOString(), requires2FA: true,
        ipAddress: req.ip, userAgent: req.get("User-Agent"),
        deviceInfo, deviceId: null, sessionType: "pending_2fa", loginMethod: "google",
      };
      await databaseManager.query(
        "INSERT INTO appblddbo.TwoFactorSession (SessionToken, UserLogin, LastUsedTS, SessionInfo) VALUES (?,?,CURRENT_TIMESTAMP,?)",
        [sessionToken, loginName, JSON.stringify(sessionData)]
      );
      log("INFO", `Google login pending 2FA for: ${loginName}`);
      return sendPopupResponse(res, frontendURL, { token: sessionToken, step: "verify_2fa", username: loginName });
    } else {
      const sessionData = {
        username: loginName, userId: userIdInt, originalPassword: null,
        loginTime: new Date().toISOString(), requires2FA: false,
        ipAddress: req.ip, userAgent: req.get("User-Agent"),
        deviceInfo, deviceId: null, sessionType: "authenticated",
        authenticated2FA: true, loginMethod: "google",
      };
      await databaseManager.query(
        "INSERT INTO appblddbo.TwoFactorSession (SessionToken, UserLogin, LastUsedTS, SessionInfo) VALUES (?,?,CURRENT_TIMESTAMP,?)",
        [sessionToken, loginName, JSON.stringify(sessionData)]
      );
      log("INFO", `Google login authenticated for: ${loginName}`);
      return sendPopupResponse(res, frontendURL, { token: sessionToken, username: loginName });
    }
  } catch (err) {
    log("ERROR", "Google OAuth callback error", { error: err.message });
    return sendPopupResponse(res, frontendURL, { error: "Internal server error during Google login" });
  }
});

router.get("/google/status", (req, res) => {
  res.json({ success: true, enabled: !!(config.google?.clientId) });
});

module.exports = router;
