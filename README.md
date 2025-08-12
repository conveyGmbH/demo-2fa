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

* Create an environment file ".env" in backend/src using .env.template, with special notice to
	* DB_UID, contains the database user, usually TFModule
    * DB_PWD, contains the password to access the database
	* DB_DSN, contains the ODBC datasource name
	* TOTP_LABEL, usually "Leadsuccess DEIMOS" for Development, "Leadsuccess LSTEST" for Test/staging
      and "Leadsuccess Portal" for production environment
	* NODE_ENV, set to "production" or "development"
* Install and start the Windows service by executing "node install-service.js" in backend\src\config
* Uninstall service by executing "node uninstall-service.js" in backend\src\config

### Frontend

Nothing to do?