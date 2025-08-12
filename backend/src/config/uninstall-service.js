var Service = require('node-windows').Service;
var inUninstall = false;

// Create a new service object
var svc = new Service({
  name:'convey 2FA Backend Service',
});

svc.on('stop',function(){
  if (!inUninstall) {
	console.log('Service stopped, uninstalling...');
	inUninstall = true;
	svc.uninstall();
  } else {
    console.log("Already uninstalling...");
  }
});

// Listen for the "uninstall" event so we know when it's done.
svc.on('uninstall',function(){
  console.log('Uninstall complete.');
  console.log('The service exists: ',svc.exists);
});


svc.stop();