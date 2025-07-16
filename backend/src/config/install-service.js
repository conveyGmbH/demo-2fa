var Service = require('node-windows').Service;

// Create a new service object
var svc = new Service({
  name:'2FA Backend Service',
  description: '2FA Backend Service',
  script: 'C:\\convey\\Services\\demo-2fa\\backend\\src\\server.js',
});

// Listen for the "install" event, which indicates the
// process is available as a service.
svc.on('install',function(){
  svc.start();
});

svc.install();