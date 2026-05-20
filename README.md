# convey Two Factor Module

The convey Two Factor Module is a module designed for the convey LeadSuccess Portal.
It consists of the frontend part, which is integrated on the client side, and the backend part
which implements a node service implementing the crypto parts of the Two Factor protocols.

Currently it only supports TOTP authentication, but FIDO-Stick / Passkey are planned extensions.

## Installation

* Clone the project from https://github.com/conveyGmbH/demo-2fa.git, usually into F:\convey\Services. 
* In the backend\src call "npm install"
* Create an environment file ".env" in backend using .env.template, with special notice to
	* DB_UID, contains the database user, usually TFModule
    * DB_PWD, contains the password to access the database
	* DB_DSN, contains the ODBC datasource name
	* TOTP_ISSUER, usually "convey LeadSuccess DEIMOS" for Development, "convey LeadSuccess LSTEST" for Test/staging
      and "convey LeadSuccess Portal" for production environment
	* NODE_ENV, set to "production" or "development"
* Install and start the Windows service by executing "node install-service.js" in backend\src\config
* Uninstall service by executing "node uninstall-service.js" in backend\src\config

**Note:** If the service should be moved/copied to another machine by copying the whole directory
tree the "daemon" directory has to be deleted before installation! This is not the recommended procedure,
we recommend to copy the ".env" file from the old server to a newly cloned directory.


### Frontend

The frontend directory is only used during development.
