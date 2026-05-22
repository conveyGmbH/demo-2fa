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

router.get("/salesforce", (req, res) => {
  if (!config.salesforce?.clientId) {
    return res.status(503).json({ success: false, message: "Salesforce OAuth not configured" });
  }
  const state = generateOAuthState();
  const loginUrl = config.salesforce.loginUrl || "https://login.salesforce.com";
  const params = new URLSearchParams({
    client_id: config.salesforce.clientId,
    redirect_uri: config.salesforce.callbackURL,
    response_type: "code",
    scope: "openid email profile",
    state,
    prompt: "login",
  });
  res.redirect(`${loginUrl}/services/oauth2/authorize?${params}`);
});

router.get("/salesforce/callback", async (req, res) => {
  const frontendURL = process.env.FRONTEND_URL || "http://localhost:3000";
  const { code, state, error } = req.query;

  if (error) return sendPopupResponse(res, frontendURL, { error });
  if (!state || !oauthStates.has(state)) {
    return sendPopupResponse(res, frontendURL, { error: "Invalid or expired OAuth state" });
  }
  oauthStates.delete(state);

  try {
    const loginUrl = config.salesforce.loginUrl || "https://login.salesforce.com";

    const tokenRes = await fetch(`${loginUrl}/services/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code,
        grant_type: "authorization_code",
        client_id: config.salesforce.clientId,
        client_secret: config.salesforce.clientSecret,
        redirect_uri: config.salesforce.callbackURL,
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error("Salesforce token exchange failed");

    const infoRes = await fetch(`${loginUrl}/services/oauth2/userinfo`, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const userInfo = await infoRes.json();
    if (!userInfo.preferred_username && !userInfo.email) throw new Error("Could not retrieve identity from Salesforce");

    const sfUsername = userInfo.preferred_username || userInfo.email;
    log("INFO", `Salesforce login attempt for: ${sfUsername}`);

    const mitarbeiterRows = await databaseManager.query(
      "SELECT * FROM appblddbo.Mitarbeiter WHERE \"Login\" = ?", [sfUsername]
    );
    if (!mitarbeiterRows.length) {
      return sendPopupResponse(res, frontendURL, { error: `No portal account found for ${sfUsername}` });
    }

    const loginName = sfUsername;
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
        deviceInfo, deviceId: null, sessionType: "pending_2fa", loginMethod: "salesforce",
      };
      await databaseManager.query(
        "INSERT INTO appblddbo.TwoFactorSession (SessionToken, UserLogin, LastUsedTS, SessionInfo) VALUES (?,?,CURRENT_TIMESTAMP,?)",
        [sessionToken, loginName, JSON.stringify(sessionData)]
      );
      log("INFO", `Salesforce login pending 2FA for: ${loginName}`);
      return sendPopupResponse(res, frontendURL, { token: sessionToken, step: "verify_2fa", username: loginName });
    } else {
      const sessionData = {
        username: loginName, userId: userIdInt, originalPassword: null,
        loginTime: new Date().toISOString(), requires2FA: false,
        ipAddress: req.ip, userAgent: req.get("User-Agent"),
        deviceInfo, deviceId: null, sessionType: "authenticated",
        authenticated2FA: true, loginMethod: "salesforce",
      };
      await databaseManager.query(
        "INSERT INTO appblddbo.TwoFactorSession (SessionToken, UserLogin, LastUsedTS, SessionInfo) VALUES (?,?,CURRENT_TIMESTAMP,?)",
        [sessionToken, loginName, JSON.stringify(sessionData)]
      );
      log("INFO", `Salesforce login authenticated for: ${loginName}`);
      return sendPopupResponse(res, frontendURL, { token: sessionToken, username: loginName });
    }
  } catch (err) {
    log("ERROR", "Salesforce OAuth callback error", { error: err.message });
    return sendPopupResponse(res, frontendURL, { error: "Internal server error during Salesforce login" });
  }
});

router.get("/salesforce/status", (req, res) => {
  res.json({ success: true, enabled: !!(config.salesforce?.clientId) });
});

module.exports = router;
