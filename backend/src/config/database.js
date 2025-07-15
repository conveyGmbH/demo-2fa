const odbc = require('odbc');

// Load environment variables from .env file
require('dotenv').config();

const config = {
  Database: {
    DSN: process.env.DB_DSN,
    UID: process.env.DB_UID,
    PWD: process.env.DB_PWD,
  }
};

// Global connection variable 
let connection;

function getDateString() {
    const currentDate = new Date();
    const [dYear, dMonth, dDay, dHour, dMinute, dSeconds, dMsec] = [
      currentDate.getFullYear(),
      currentDate.getMonth(),
      currentDate.getDate(),
      currentDate.getHours(),
      currentDate.getMinutes(),
      currentDate.getSeconds(),
      currentDate.getMilliseconds(),
    ];
          
    return dDay.toString().padStart(2, '0')+'.'+(dMonth+1).toString().padStart(2, '0')+'. '+
           dHour.toString().padStart(2, '0')+':'+dMinute.toString().padStart(2, '0')+':'+dSeconds.toString().padStart(2, '0')+
           '.'+dMsec.toString().padStart(3, '0');
}


async function connectToDB() {
    try {
        const connectionString = 
            'DSN=' + config.Database.DSN + 
            ';UID=' + config.Database.UID + 
            ';PWD=' + config.Database.PWD + 
            ';CHARSET=UTF8';

        connection = await odbc.connect(connectionString);

        console.log('Connected to the database');

    } catch (error) {
        console.error(getDateString(), '❌ Error connecting to the database:', error);
        setTimeout(connectToDB, 5000); 
    }
}


async function displayTwoFactorUsers() {
    try {
        const users = await connection.query('SELECT * FROM appblddbo.TwoFactorUser');
        
        if (users.length === 0) {
            console.log('No users found in TwoFactorUser table');
        } else {
            console.log(`   📊 Found ${users.length} user(s):`);
            users.forEach((user, index) => {
                console.log(`   ${index + 1}. User ID: ${user.TwoFactorUserID}`);
                console.log(`      Login: ${user.LoginName}`);
                console.log(`      Disable2FA: ${user.Disable2FA ? 'Yes' : 'No'}`);
                console.log(`      Created: ${user.CreatedDate || 'N/A'}`);
                console.log(`      Last Login: ${user.LastLoginDate || 'Never'}`);
                console.log('      ---');
            });
        }
    } catch (error) {
        console.error('   ❌ Error reading TwoFactorUser table:', error.message);
    }
}

// Function to display TwoFactorDevice table
async function displayTwoFactorDevices() {
    try {
        console.log('\n🔐 === TwoFactorDevice Table ===');
        const devices = await connection.query('SELECT * FROM appblddbo.TwoFactorDevice');
        
        if (devices.length === 0) {
            console.log('   ℹ️  No devices found in TwoFactorDevice table');
        } else {
            console.log(`   📊 Found ${devices.length} device(s):`);
            devices.forEach((device, index) => {
                console.log(`   ${index + 1}. Device ID: ${device.TwoFactorDeviceID}`);
                console.log(`      User ID: ${device.TwoFactorUserID}`);
                console.log(`      Auth Method: ${device.AuthMethod}`);
                console.log(`      Device Info: ${device.DeviceInfo || 'No description'}`);
                console.log(`      Status: ${device.Inactive ? '❌ Inactive' : '✅ Active'}`);
                console.log(`      Created: ${device.CreatedDate || 'N/A'}`);
                console.log('      ---');
            });
        }
    } catch (error) {
        console.error('   ❌ Error reading TwoFactorDevice table:', error.message);
    }
}

// Function to display TwoFactorSession 
async function displayTwoFactorSessions() {
    try {
        console.log('\n🔑 === TwoFactorSession Table ===');
        const sessions = await connection.query('SELECT SessionToken, UserLogin, LastUsedTS FROM appblddbo.TwoFactorSession');
        
        if (sessions.length === 0) {
            console.log('   ℹ️  No active sessions found');
        } else {
            console.log(`   📊 Found ${sessions.length} session(s):`);
            sessions.forEach((session, index) => {
                console.log(`   ${index + 1}. User: ${session.UserLogin}`);
                console.log(`      Session: ${session.SessionToken.substring(0, 8)}...`);
                console.log(`      Last Used: ${session.LastUsedTS}`);
                console.log('      ---');
            });
        }
    } catch (error) {
        console.error('   ❌ Error reading TwoFactorSession table:', error.message);
    }
}

// Function to display database summary
async function displayDatabaseSummary() {
    try {
        console.log('\n📈 === Database Summary ===');
        
        // Count users
        const userCount = await connection.query('SELECT COUNT(*) as count FROM appblddbo.TwoFactorUser');
        console.log(` Total Users: ${userCount[0].count}`);
        
        // Count devices
        const deviceCount = await connection.query('SELECT COUNT(*) as count FROM appblddbo.TwoFactorDevice');
        console.log(`Total Devices: ${deviceCount[0].count}`);
        
        // Count active devices
        const activeDeviceCount = await connection.query('SELECT COUNT(*) as count FROM appblddbo.TwoFactorDevice WHERE Inactive = 0');
        console.log(` Active Devices: ${activeDeviceCount[0].count}`);
        
        // Count sessions
        const sessionCount = await connection.query('SELECT COUNT(*) as count FROM appblddbo.TwoFactorSession');
        console.log(` Active Sessions: ${sessionCount[0].count}`);
        
        console.log('=====================================\n');
        
    } catch (error) {
        console.error('Error getting database summary:', error.message);
    }
}

// Main function to display all tables at startup
async function displayTablesAtStartup() {
    if (!connection) {
        console.log('Cannot display tables: database not connected');
        return;
    }
    
    console.log(getDateString(), ' Loading database tables...\n');
    
    try {
        await displayDatabaseSummary();
        await displayTwoFactorUsers();
        await displayTwoFactorDevices();
        await displayTwoFactorSessions();
        
        console.log('✅ Database overview complete!\n');
    } catch (error) {
        console.error('❌ Error during database overview:', error);
    }
}

// Function to display specific table
async function displayTable(tableName) {
    try {
        console.log(`\n📋 === ${tableName} Table ===`);
        const result = await connection.query(`SELECT * FROM appblddbo.${tableName}`);
        
        if (result.length === 0) {
            console.log(`   ℹ️  No records found in ${tableName} table`);
        } else {
            console.log(`   📊 Found ${result.length} record(s):`);
            console.table(result);
        }
    } catch (error) {
        console.error(`   ❌ Error reading ${tableName} table:`, error.message);
    }
}


// Simple database manager object 
const databaseManager = {
    // Connect method
    async connect() {
        return await connectToDB();
    },

    // Get connection
    getConnection() {
        if (!connection) {
            throw new Error('Database not connected');
        }
        return connection;
    },

    // Execute query
    async query(sql, params = []) {
        try {
            if (!connection) {
                throw new Error('Database not connected');
            }
            const result = await connection.query(sql, params);
            return result;
        } catch (error) {
            console.error(getDateString(), ' Database query error:', error);
            throw error;
        }
    },

    // Health check
    async healthCheck() {
        try {
            if (!connection) {
                return false;
            }
            const result = await connection.query('SELECT 1 as test');
            return result && result.length > 0;
        } catch (error) {
            console.error('Health check failed:', error);
            return false;
        }
    },

    // Close connection
    async close() {
        if (connection) {
            try {
                await connection.close();
                console.log('✅ Database connection closed');
            } catch (error) {
                console.error('❌ Error closing database connection:', error);
            }
            connection = null;
        }
    },


    // Manual table display functions
    displayUsers: displayTwoFactorUsers,
    displayDevices: displayTwoFactorDevices,
    displaySessions: displayTwoFactorSessions,
    displaySummary: displayDatabaseSummary,
    displayTable: displayTable,
    displayAll: displayTablesAtStartup,

    // Get status
    isConnected() {
        return !!connection;
    }
};

module.exports = databaseManager;