var Service = require('node-windows').Service;
const path = require('path');

// Create a new service object
// workingDirectory must point to the directory containing the .env file 
var svc = new Service({
  name:'convey 2FA Backend Service',
  description: 'convey 2FA Backend Service',
  script: path.resolve(__dirname, '..\\')+'\\server.js',
  workingDirectory: path.resolve(__dirname, '..\\..\\'),
});

// Listen for the "install" event, which indicates the
// process is available as a service.
svc.on("install", function () {
  // I prefer not to automatically start the service after installation...
  console.log("Service is installed.");
  // svc.start();
});

svc.install();