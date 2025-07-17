const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const databaseManager = require("./config/database");
const { errorHandler, notFoundHandler } = require("./middleware/errorHandler");
const logger = require("./utils/logger");
const config = require("./config/config.js");

// Load environment variables from .env file
require("dotenv").config();

console.log("🚀 Starting server...");

// Import routes with error handling
let routes;
try {
  routes = require("./routes");
  console.log("Routes imported successfully");
} catch (error) {
  console.error("Error importing routes:", error.message);
  console.log("Server will start without routes - check routes/index.js");
}

class Server {
  constructor() {
    this.app = express();
    this.setupMiddleware();
    this.setupRoutes();
    this.app.use((err, req, res, next) => {
    console.log('🔥 PARSING ERROR:', {
        error: err.message,
        stack: err.stack,
        body: req.body,
        headers: req.headers,
        method: req.method,
        url: req.url
    });
    
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
    console.log("🔧 Setting up middleware...");

    this.app.use(helmet());

    this.app.use((req, res, next) => {
      console.log("🔍 DEBUG REQUEST:", {
        method: req.method,
        url: req.url,
        headers: req.headers,
        contentType: req.get("Content-Type"),
        body: req.body,
        rawBody: req.body ? JSON.stringify(req.body) : "NO BODY",
        timestamp: new Date().toISOString(),
      });
      next();
    });

    const corsOptions = {
      origin: function (origin, callback) {
        if (!origin) return callback(null, true);

        // List of allowed origins
        const allowedOrigins = [
          // Production URLs
          "https://deimos.convey.de",

          // Dev URLs
          "http://localhost:51170",
          "http://localhost:4000",
        ];

        // In development, allow all localhost origins
        if (process.env.NODE_ENV !== "production") {
          if (
            origin.startsWith("http://localhost:") ||
            origin.startsWith("http://127.0.0.1:")
          ) {
            return callback(null, true);
          }
        }

        // Check if the origin is in the allowed list
        if (allowedOrigins.indexOf(origin) !== -1) {
          callback(null, true);
        } else {
          console.log(`CORS: Origin not allowed: ${origin}`);
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
    // this.app.use(express.json({ type: 'application/json', limit: '10mb' }));
    this.app.use(
      express.json({
        type: ["application/json", "text/plain"],
        limit: "10mb",
        verify: (req, res, buf, encoding) => {
          console.log("🔍 JSON PARSING:", {
            contentType: req.get("Content-Type"),
            contentLength: req.get("Content-Length"),
            bufferLength: buf.length,
            encoding: encoding,
          });
        },
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
    console.log("Setting up routes...");

    // Root endpoint
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

    // CORS test endpoint
    this.app.get("/cors-test", (req, res) => {
      res.json({
        success: true,
        message: "CORS is working correctly",
        origin: req.get("Origin"),
        timestamp: new Date().toISOString(),
      });
    });

    // Mount API routes if available
    if (routes) {
      this.app.use("/api/v1", routes);
      console.log("✅ API routes mounted on /api/v1");
    } else {
      // Fallback endpoint if routes failed to load
      this.app.get("/api/v1", (req, res) => {
        res.json({
          success: false,
          message: "Routes not loaded - check server logs",
          timestamp: new Date().toISOString(),
        });
      });
      console.log("⚠️ Routes not mounted - using fallback");
    }
  }
    

  setupErrorHandling() {
    console.log("🛡️ Setting up error handling...");
    this.app.use(notFoundHandler);
    this.app.use(errorHandler);
    console.log("✅ Error handling setup complete");
  }

  async start() {
    try {
      console.log("🔌 Connecting to the database...");
      await databaseManager.connect();
      console.log("✅ Database connected");

      const port = process.env.PORT || 4000;
      console.log("Starting server on port:", port);

      this.app.listen(port, () => {
        logger.info(`Server listening on port ${port}`);

        console.log("");
        console.log(" SERVER READY!");
        console.log(` Server: http://localhost:${port}`);
        console.log(` Root: http://localhost:${port}/`);
        console.log(` Health: http://localhost:${port}/api/v1/health`);
        console.log(` DB Test: http://localhost:${port}/api/v1/test-db`);
        console.log(` CORS Test: http://localhost:${port}/cors-test`);
        console.log("");
        console.log("📋 Available endpoints:");
        if (routes) {
          console.log("   GET  /api/v1/health - Health check");
          console.log("   GET  /api/v1/test-db - Database test");
          console.log("   GET  /api/v1/tables - Show all tables overview");

          console.log("   POST /api/v1/auth/login - User login");
          console.log("   POST /api/v1/auth/setup-2fa - Setup 2FA");
          console.log("   POST /api/v1/auth/verify-2fa - Verify 2FA");
          console.log("   POST /api/v1/auth/disable-2fa - Disable 2FA");
          console.log("   POST /api/v1/auth/status - User status");
        } else {
          console.log("⚠️ No routes loaded - check routes/index.js");
        }
        console.log("");
        console.log("🔒 CORS Configuration:");
        console.log("   ✅ Development: All localhost ports allowed");
        console.log("   ✅ Credentials: Enabled");
        console.log(
          "   ✅ Headers: Content-Type, Authorization, X-Session-Token"
        );
        console.log("");
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
    console.error("🔥 Fatal error starting server:", err);
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
