var Service = require('node-windows').Service;

// ToDo: Make pathes relative...

// Create a new service object
// workingDirectory must point to the directory containing the .env file 
var svc = new Service({
  name:'convey 2FA Backend Service',
  description: 'convey 2FA Backend Service',
  script: 'C:\\convey\\Services\\demo-2fa\\backend\\src\\server.js',
  workingDirectory: 'C:\\convey\\Services\\demo-2fa\\backend',
});

// Listen for the "install" event, which indicates the
// process is available as a service.
svc.on('install',function(){
  svc.start();
});

svc.install();