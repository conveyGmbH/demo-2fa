# convey Two Factor Module

The convey Two Factor Module is a module designed for the convey LeadSuccess Portal.
It consists of the frontend part, which is integrated on the client side, and the backend part
which implements a node service implementing the crypto parts of the Two Factor protocols.

Currently it only supports TOTP authentication, but FIDO-Stick / Passkey are planned extensions.

## Installation

Clone the project from [https://github.com/conveyGmbH/demo-2fa.git], usually into c:\convey\Services

### Backend

* Create an environment file ".env" in backend.src (ToDo: Template?), with special notice to
	* DB_UID, contains the database user, usually TFModule
    * DB_PWD, contains the password to access the database
	* DB_DSN, contains the ODBC datasource name
	* TOTP_LABEL, usually "Leadsuccess DEIMOS" for Development, "Leadsuccess LSTEST" for Test 
      and "Leadsuccess Portal" for production environment
* Install and start the Windows service by executing "node install-service.js" in backend\src\config

Something else?

### Frontend

ToDo... 