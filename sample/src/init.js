// copies js file from the node_modules folder for use by the html pages in ./public
var fs = require('fs');
fs.copyFileSync('node_modules/jsqr/dist/jsQR.js', 'public/jsQR.js');
console.log("Copied QR-scanner scripts to ./public");
