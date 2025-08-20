# convey Two Factor Module

The convey Two Factor Module is a module designed for the convey LeadSuccess Portal.
It consists of the frontend part, which is integrated on the client side, and the backend part
which implements a node service implementing the crypto parts of the Two Factor protocols.

Currently it only supports TOTP authentication, but FIDO-Stick / Passkey are planned extensions.

## Installation

Clone the project from https://github.com/conveyGmbH/demo-2fa.git, usually into c:\convey\Services. 

**Note:** Currently the install and uninstall scripts contain absolute pathnames and work only
if the modult is installed in c:\convey\services. This should be fixed some time in the future...

### Backend

* Create an environment file ".env" in backend/ using .env.template, with special notice to
	* DB_UID, contains the database user, usually TFModule
    * DB_PWD, contains the password to access the database
	* DB_DSN, contains the ODBC datasource name
	* TOTP_ISSUER, usually "convey LeadSuccess DEIMOS" for Development, "convey LeadSuccess LSTEST" for Test/staging
      and "convey LeadSuccess Portal" for production environment
	* NODE_ENV, set to "production" or "development"
* Install dependencies by starting "npm install" in backend\src\config
* Install and start the Windows service by executing "node install-service.js" in backend\src\config. 
  ToDo: Create installation script which integrates this step in the "npm install"...
* Check allowed origins in backend/src/serverjs, search for "corsOption". Installation location must be 
  included in the allowerOrigins array. ToDo: Allow configuration by .env file
* Create Rewrite Rule (ToDo: Create a PowerShell script for that):
    * Start IIS Manager, go to the Server-Node and start URL Rewrite applet
	* "Add Rule(s)...", select "Blank Rule"
	* Name (by convention) "TwoFactorService"
	* Leave "Requested URL" at "Matches the Pattern" and "Using" at "Regular Expressions"
	* Pattern (imortant, must match value in twoFactorLib.js!): "^2fabackend(/.*)" 
	* Leave "Ignore case" active (by convention)
	* Do not modify "Conditions" and "Server Variables"
	* Action type: "Rewrite", "Rewrite URL" is "http://localhost:4000{R:1}" (Port must match the .env value "PORT="?)
	* "Append query string" must be active
	* "Stop processing ..." stays deactivated
* Uninstall service by executing "node uninstall-service.js" in backend\src\config

ToDo: Directory usage is confusing, maybe remove the "backend" directory level?

### Frontend

Nothing to do?