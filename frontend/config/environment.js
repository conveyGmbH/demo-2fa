
const isProduction = window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1';

// ✅ Configuration des URLs selon l'environnement
const config = {
    // Environment detection
    isProduction: isProduction,
    environment: isProduction ? 'production' : 'development',
    
    // API Base URLs
    api: {
        baseURL: isProduction 
            ? 'https://ls2fabackend-fthub6cvegdeagbv.westeurope-01.azurewebsites.net//api/v1' 
            : 'http://localhost:4000/api/v1',
        timeout: 30000 // 30 seconds
    },
    
    // App configuration
    app: {
        name: 'LeadSuccess 2FA Portal',
        version: '1.0.0',
        frontendURL: isProduction 
            ? 'https://brave-bay-061146803.1.azurestaticapps.net'
            : window.location.origin
    },
    
    // Security settings
    security: {
        sessionTimeout: 30 * 60 * 1000, // 30 minutes
        maxLoginAttempts: 3,
        lockoutDuration: 15 * 60 * 1000 // 15 minutes
    },
    
    // Logging level
    logging: {
        level: isProduction ? 'ERROR' : 'DEBUG',
        enableConsole: !isProduction
    }
};

// Export configuration
window.AppConfig = config;

// Log configuration for debugging
if (config.logging.enableConsole) {
    console.log('App Configuration:', config);
}