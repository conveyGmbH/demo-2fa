const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const databaseManager = require('./config/database');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');
const logger = require('./utils/logger');
const config = require('./config/config.js');

console.log('🚀 Starting server...');

// Import routes with error handling
let routes;
try {
    routes = require('./routes');
    console.log('✅ Routes imported successfully');
} catch (error) {
    console.error('❌ Error importing routes:', error.message);
    console.log('⚠️ Server will start without routes - check routes/index.js');
}

class Server {
    constructor() {
        this.app = express();
        this.setupMiddleware();
        this.setupRoutes();
        this.setupErrorHandling();
    }

    setupMiddleware() {
        console.log('🔧 Setting up middleware...');
        
        this.app.use(helmet());
        
        const corsOptions = {
            origin: function (origin, callback) {
                if (!origin) return callback(null, true);
                
                // Liste des origines autorisées
                const allowedOrigins = [
                    'http://localhost:3000',
                    'http://localhost:5005',
                    'http://localhost:5006',
                    'http://localhost:5500',
                    'http://localhost:5501',
                    'http://localhost:5502',
                    'http://localhost:5503',
                    'http://localhost:5504',
                    'http://localhost:5505',
                    'http://localhost:5506',
                    'http://localhost:5507',
                    'http://localhost:5508',
                    'http://localhost:5509',
                    'http://localhost:8080',
                    'http://localhost:8000',
                    'http://127.0.0.1:5500',
                    'http://127.0.0.1:5501',
                    'http://127.0.0.1:5502',
                    'http://127.0.0.1:5503',
                    'http://127.0.0.1:5504',
                    'http://127.0.0.1:5505',
                    'http://127.0.0.1:5506',
                    'http://127.0.0.1:5507',
                    'http://127.0.0.1:5508',
                    'http://127.0.0.1:5509',
                    'http://localhost:51170',
                    'http://localhost:4000',
                ];

                // En développement, autoriser toutes les origines localhost
                if (process.env.NODE_ENV !== 'production') {
                    if (origin.startsWith('http://localhost:') || origin.startsWith('http://127.0.0.1:')) {
                        return callback(null, true);
                    }
                }

                // Vérifier si l'origine est dans la liste autorisée
                if (allowedOrigins.indexOf(origin) !== -1) {
                    callback(null, true);
                } else {
                    console.log(`❌ CORS: Origin not allowed: ${origin}`);
                    callback(new Error('Not allowed by CORS'));
                }
            },
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization', 'X-Session-Token', 'X-Requested-With'],
            exposedHeaders: ['X-Session-Token']
        };

        this.app.use(cors(corsOptions));
        
        this.app.use(compression());
        this.app.use(express.json({ type: 'application/json', limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));

        const limiter = rateLimit({
            windowMs: config.security?.rateLimitWindow || 15 * 60 * 1000,
            max: config.security?.rateLimitMax || 100,
            message: {
                success: false,
                message: 'Too many requests, please try again later'
            }
        });
        this.app.use(limiter);

        // this.app.use((req, res, next) => {
        //     logger.info(`${req.method} ${req.path}`, {
        //         ip: req.ip,
        //         origin: req.get('Origin'),
        //         userAgent: req.get('User-Agent'),
        //         body: req.method === 'POST' ? '***REDACTED***' : undefined
        //     });
        //     next();
        // });
        
        console.log('✅ Middleware setup complete');
    }

    setupRoutes() {
        console.log('🛣️ Setting up routes...');
        
        // Root endpoint
        this.app.get('/', (req, res) => {
            res.json({
                success: true,
                message: 'LeadSuccess 2FA Server',
                timestamp: new Date().toISOString(),
                status: 'running',
                api: '/api/v1',
                cors: {
                    enabled: true,
                    development: process.env.NODE_ENV !== 'production' ? 'All localhost origins allowed' : 'Restricted origins only'
                }
            });
        });

        // CORS test endpoint
        this.app.get('/cors-test', (req, res) => {
            res.json({
                success: true,
                message: 'CORS is working correctly',
                origin: req.get('Origin'),
                timestamp: new Date().toISOString()
            });
        });

        // Mount API routes if available
        if (routes) {
            this.app.use('/api/v1', routes);
            console.log('✅ API routes mounted on /api/v1');
        } else {
            // Fallback endpoint if routes failed to load
            this.app.get('/api/v1', (req, res) => {
                res.json({
                    success: false,
                    message: 'Routes not loaded - check server logs',
                    timestamp: new Date().toISOString()
                });
            });
            console.log('⚠️ Routes not mounted - using fallback');
        }
    }

    setupErrorHandling() {
        console.log('🛡️ Setting up error handling...');
        this.app.use(notFoundHandler);
        this.app.use(errorHandler);
        console.log('✅ Error handling setup complete');
    }

    async start() {
        try {
            console.log('🔌 Connecting to the database...');
            await databaseManager.connect();
            console.log('✅ Database connected');

            const port = 4000;
            console.log("🚀 Starting server on port:", port);
            
            this.app.listen(port, () => {
                logger.info(`Server listening on port ${port}`);
                
                console.log('');
                console.log('🎉 SERVER READY!');
                console.log(`🔗 Server: http://localhost:${port}`);
                console.log(`🏠 Root: http://localhost:${port}/`);
                console.log(`💚 Health: http://localhost:${port}/api/v1/health`);
                console.log(`🗃️ DB Test: http://localhost:${port}/api/v1/test-db`);
                console.log(`🌐 CORS Test: http://localhost:${port}/cors-test`);
                console.log('');
                console.log('📋 Available endpoints:');
                if (routes) {
                    console.log('   GET  /api/v1/health - Health check');
                    console.log('   GET  /api/v1/test-db - Database test');
                    console.log('   GET  /api/v1/tables - Show all tables overview');
                    console.log('   GET  /api/v1/tables/TwoFactorUser - User table');
                    console.log('   GET  /api/v1/tables/TwoFactorDevice - Device table');
                    console.log('   GET  /api/v1/tables/TwoFactorSession - Session table');
                    console.log('   POST /api/v1/auth/login - User login');
                    console.log('   POST /api/v1/auth/setup-2fa - Setup 2FA');
                    console.log('   POST /api/v1/auth/verify-2fa - Verify 2FA');
                    console.log('   POST /api/v1/auth/disable-2fa - Disable 2FA');
                    console.log('   POST /api/v1/auth/status - User status');
                } else {
                    console.log('   ⚠️ No routes loaded - check routes/index.js');
                }
                console.log('');
                console.log('🔒 CORS Configuration:');
                console.log('   ✅ Development: All localhost ports allowed');
                console.log('   ✅ Credentials: Enabled');
                console.log('   ✅ Headers: Content-Type, Authorization, X-Session-Token');
                console.log('');
            });
        } catch (error) {
            console.error('❌ Failed to start server:', error);
            logger.error('Failed to start server:', error);
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
        console.error('🔥 Fatal error starting server:', err);
        process.exit(1);
    }
})();

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('🛑 SIGTERM received, shutting down gracefully');
    logger.info('SIGTERM received, shutting down gracefully');
    await databaseManager.close();
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('🛑 SIGINT received, shutting down gracefully');
    logger.info('SIGINT received, shutting down gracefully');
    await databaseManager.close();
    process.exit(0);
});

module.exports = Server;