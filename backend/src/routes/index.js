const express = require("express");
const databaseManager = require("../config/database");
const { log } = require("../services/totpService");

const authCredentials = require("./auth/credentials");
const authTotp       = require("./auth/totp");
const authGoogle     = require("./auth/google");
const authSalesforce = require("./auth/salesforce");
const devices        = require("./devices");
const sessions       = require("./sessions");

const router = express.Router();

router.get("/", (req, res) => {
  res.json({
    success: true,
    message: "LeadSuccess 2FA API",
    timestamp: new Date().toISOString(),
    endpoints: {
      authentication: {
        login: "POST /auth/login",
        checkCredentials: "POST /auth/check-credentials",
        setup2fa: "POST /auth/setup-2fa",
        verify2fa: "POST /auth/verify-2fa",
        status: "POST /auth/status",
        disable2fa: "POST /auth/disable-2fa",
      },
      devices: {
        list: "POST /devices/list",
        add: "POST /devices/add",
        rename: "POST /devices/rename",
        remove: "POST /devices/remove",
      },
      sessions: {
        list: "POST /sessions/list",
        logout: "POST /sessions/logout",
        logoutAll: "POST /sessions/logout-all",
      },
    },
  });
});

router.get("/health", async (req, res) => {
  try {
    const dbHealthy = await databaseManager.healthCheck();
    res.status(dbHealthy ? 200 : 503).json({
      success: dbHealthy,
      message: dbHealthy ? "Service healthy" : "Database connection failed",
      timestamp: new Date().toISOString(),
      services: { database: dbHealthy ? "healthy" : "unhealthy", api: "healthy", totp: "healthy" },
    });
  } catch (error) {
    log("ERROR", "Health check error", { error: error.message });
    res.status(503).json({ success: false, message: "Health check failed", error: error.message });
  }
});

router.use("/auth", authCredentials);
router.use("/auth", authTotp);
router.use("/auth", authGoogle);
router.use("/auth", authSalesforce);
router.use("/devices", devices);
router.use("/sessions", sessions);

module.exports = router;
