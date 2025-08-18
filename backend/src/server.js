const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const databaseManager = require("./config/database");
const { errorHandler, notFoundHandler } = require("./middleware/errorHandler");
const logger = require("./utils/logger");
const config = require("./config/config.js");

// load environment variables from .env file
require("dotenv").config();

let routes;
try {
  routes = require("./routes");
  console.log("Routes imported successfully");
} catch (error) {
  console.error("Error importing routes:", error.message);
}

class Server {
  constructor() {
    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
    this.app.use((err, req, res, next) => {    
    if (err.type === 'entity.parse.failed') {
        return res.status(400).json({
            success: false,
            message: 'Invalid JSON in request body',
            error: err.message
        });
    }
    next(err);
});
    this.setupErrorHandling();
  }

  setupMiddleware() {

    this.app.use(helmet());

    const corsOptions = {
      origin: function (origin, callback) {
        if (!origin) return callback(null, true);

        // list of allowed origins
        const allowedOrigins = [
          // production URLs
          "https://deimos.convey.de",
          "https://lstest.convey.de",

          // dev URLs
          "http://localhost:51170",
          "http://localhost:51171",
          "http://localhost:4000",
        ];

        // In development, allow all localhost origins
        if (process.env.NODE_ENV !== "production") {
          if (origin.startsWith("http://localhost:") ||origin.startsWith("http://127.0.0.1:")) {
            return callback(null, true);
          }
        }

        // Check if the origin is in the allowed list
        if (allowedOrigins.indexOf(origin) !== -1) {
          callback(null, true);
        } else {
          callback(new Error("Not allowed by CORS"));
        }
      },
      credentials: true,
      methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
      allowedHeaders: [
        "Content-Type",
        "Authorization",
        "X-Session-Token",
        "X-Requested-With",
      ],
      exposedHeaders: ["X-Session-Token"],
    };

    this.app.use(cors(corsOptions));

    this.app.use(compression());
    this.app.use(express.json({
        type: ["application/json", "text/plain"],
        limit: "10mb",
      })
    );

    this.app.use(express.urlencoded({ extended: true, limit: "10mb" }));

    const limiter = rateLimit({
      windowMs: config.security?.rateLimitWindow || 15 * 60 * 1000,
      max: config.security?.rateLimitMax || 100,
      message: {
        success: false,
        message: "Too many requests, please try again later",
      },
    });
    this.app.use(limiter);
  }

  setupRoutes() {
    // root endpoint
    this.app.get("/", (req, res) => {
      res.json({
        success: true,
        message: "LeadSuccess 2FA Server",
        timestamp: new Date().toISOString(),
        status: "running",
        api: "/api/v1",
        cors: {
          enabled: true,
          development:
            process.env.NODE_ENV !== "production"
              ? "All localhost origins allowed"
              : "Restricted origins only",
        },
      });
    });

    // Mount API routes if available
    if (routes) {
      this.app.use("/api/v1", routes);     
    } else {
      // Fallback endpoint if routes failed to load
      this.app.get("/api/v1", (req, res) => {
        res.json({
          success: false,
          message: "Routes not loaded",
          timestamp: new Date().toISOString(),
        });
      });
      console.log("Routes not mounted - using fallback");
    }
  }

  setupErrorHandling() {
    this.app.use(notFoundHandler);
    this.app.use(errorHandler);
  }

  async start() {
    try {
    
      await databaseManager.connect();
      console.log(" Database connected");

      const port = process.env.PORT || 4000;

      this.app.listen(port, () => {
        logger.info(`Server listening on port ${port}`);
        console.log(" SERVER READY!");
        
        if (routes) {
          console.log("GET  /api/v1/health - Health check");
          console.log("GET  /api/v1/test-db - Database test");
          console.log("GET  /api/v1/tables - Show all tables overview");

          console.log("POST /api/v1/auth/login - User login");
          console.log("POST /api/v1/auth/setup-2fa - Setup 2FA");
          console.log("POST /api/v1/auth/verify-2fa - Verify 2FA");
          console.log("POST /api/v1/auth/disable-2fa - Disable 2FA");
          console.log("POST /api/v1/auth/status - User status");
        } else {
          console.log("No routes loaded - check routes/index.js");
        }

      });
    } catch (error) {
      console.error("❌ Failed to start server:", error);
      logger.error("Failed to start server:", error);
      process.exit(1);
    }
  }
}

// Main entry point
(async () => {
  try {
    const server = new Server();
    await server.start();
  } catch (err) {
    console.error("error starting server:", err);
    process.exit(1);
  }
})();

// Graceful shutdown
process.on("SIGTERM", async () => {
  console.log("🛑 SIGTERM received, shutting down gracefully");
  logger.info("SIGTERM received, shutting down gracefully");
  await databaseManager.close();
  process.exit(0);
});

process.on("SIGINT", async () => {
  console.log("🛑 SIGINT received, shutting down gracefully");
  logger.info("SIGINT received, shutting down gracefully");
  await databaseManager.close();
  process.exit(0);
});

module.exports = Server;
