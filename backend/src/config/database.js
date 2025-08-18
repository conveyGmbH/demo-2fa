const odbc = require('odbc');
let connection;

// load environment variables from .env file
require('dotenv').config();

const config = {
  Database: {
    DSN: process.env.DB_DSN,
    UID: process.env.DB_UID,
    PWD: process.env.DB_PWD,
  }
};


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
        console.error(getDateString(), ' Error connecting to the database '+config.Database.DSN+" as "+config.Database.UID+"\n", error);
        setTimeout(connectToDB, 5000); 
    }
}


async function displayTwoFactorUsers() {
    try {
        const users = await connection.query('SELECT * FROM appblddbo.TwoFactorUser');

        if (users.length === 0) {
            console.log('No users found in TwoFactorUser table');
        } else {
            users.forEach((user, index) => {
                console.log(` Login: ${user.LoginName}`);
            });
        }
    } catch (error) {
        console.error('Error reading TwoFactorUser table:', error.message);
    }
}

// Function to display TwoFactorDevice table
async function displayTwoFactorDevices() {
    try {
        const devices = await connection.query('SELECT * FROM appblddbo.TwoFactorDevice');
        
        if (devices.length === 0) {
            console.log('No devices found in TwoFactorDevice table');
        } else {
            console.log(` Found ${devices.length} device(s):`);
            devices.forEach((device, index) => {
                console.log(` ${index + 1}. Device ID: ${device.TwoFactorDeviceID}`);
                console.log(` User ID: ${device.TwoFactorUserID}`);
            });
        }
    } catch (error) {
        console.error('Error reading TwoFactorDevice table:', error.message);
    }
}

// Function to display TwoFactorSession 
async function displayTwoFactorSessions() {
    try {
        const sessions = await connection.query('SELECT SessionToken, UserLogin, LastUsedTS FROM appblddbo.TwoFactorSession');
        
        if (sessions.length === 0) {
            console.log(' No active sessions found');
        } else {
            console.log(` Sessions found ${sessions.length} session(s):`);
            sessions.forEach((session, index) => {
                console.log(`${index + 1}. User: ${session.UserLogin}`);
                console.log(`Last Used: ${session.LastUsedTS}`);
            });
        }
    } catch (error) {
        console.error('Error reading TwoFactorSession table:', error.message);
    }
}

// Display database summary
async function displayDatabaseSummary() {
    try {

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

    try {
        await displayDatabaseSummary();
        await displayTwoFactorUsers();
        await displayTwoFactorDevices();
        await displayTwoFactorSessions();

    } catch (error) {
        console.error(' Error during database overview:', error);
    }
}

// Function to display specific table
async function displayTable(tableName) {
    try {
        console.log(`\n === ${tableName} Table ===`);
        const result = await connection.query(`SELECT * FROM appblddbo.${tableName}`);
        
        if (result.length === 0) {
            console.log(`No records found in ${tableName} table`);
        } else {
            console.log(`Found ${result.length} record(s):`);
            console.table(result);
        }
    } catch (error) {
        console.error(`Error reading ${tableName} table:`, error.message);
    }
}


// Simple database manager object 
const databaseManager = {
    async connect() {
        return await connectToDB();
    },

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
            console.error(getDateString(), ' Database query error:', JSON.stringify(error));
			if (error.odbcErrors && error.odbcErrors[0] && error.odbcErrors[0].code == -308) {
				console.error('Retrying once...');
				try {
					await databaseManager.close();
					await databaseManager.connect();
					const result = await connection.query(sql, params);
					console.error('Retry success');
					return result;
				} catch (error) {
                  console.error(getDateString(), 'Database query error on reconnect:', error);
				  throw error;
				}
			}
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
                console.log(' Database connection closed');
            } catch (error) {
                console.error(' Error closing database connection:', error);
            }
            connection = null;
        }
    },


    // table display functions
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