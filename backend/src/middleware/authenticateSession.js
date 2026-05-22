const databaseManager = require('../config/database');
const { verifyCredentialsForEndpoint } = require('../services/totpService');
const { log } = require('../services/totpService');

async function authenticateSession(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    const sessionToken = (authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null)
      || req.headers['x-session-token']
      || req.body.sessionToken;

    if (sessionToken) {
      const sessionQuery = await databaseManager.query(
        "SELECT * FROM appblddbo.TwoFactorSession WHERE SessionToken = ? AND LastUsedTS > DATEADD(hour, -24, CURRENT_TIMESTAMP)",
        [sessionToken]
      );

      if (sessionQuery.length > 0) {
        const sessionData = JSON.parse(sessionQuery[0].SessionInfo);

        if (sessionData.authenticated2FA) {
          req.user = {
            username: sessionData.username,
            userId: sessionData.userId,
            sessionToken: sessionToken
          };
          await databaseManager.query(
            "UPDATE appblddbo.TwoFactorSession SET LastUsedTS = CURRENT_TIMESTAMP WHERE SessionToken = ?",
            [sessionToken]
          );
          return next();
        }
      }
    }

    const { username, password } = req.body;
    if (username && password) {
      const credentialsCheck = await verifyCredentialsForEndpoint(username, password);
      if (credentialsCheck.success) {
        req.user = { username, password };
        return next();
      }
    }

    return res.status(401).json({ success: false, message: "Authentication required" });

  } catch (error) {
    log("ERROR", "Authentication middleware error", { error: error.message });
    return res.status(500).json({ success: false, message: "Authentication error" });
  }
}

module.exports = authenticateSession;
