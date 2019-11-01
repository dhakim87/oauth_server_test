var secureRandom = require('secure-random');
var fs = require('fs');

var signingKey = secureRandom(256, {type: 'Buffer'}).toString('base64');
var pepper = secureRandom(16, {type: 'Buffer'}).toString('base64');
var dbPass = secureRandom(16, {type: 'Buffer'}).toString('base64');

var configObj = {};
configObj['SIGNING_KEY'] = signingKey;
configObj['PW_PEPPER'] = pepper;
configObj['DB_CONN'] = {}
configObj['DB_CONN'] =
  {
    "host": "127.0.0.1",
    "port": 5432,
    "database": "oauthdb",
    "user": "oauthdb",
    "password": dbPass
  }

fs.writeFile('config-generated.json', JSON.stringify(configObj, null, 2), function(err) {
  if (err) throw err;
  console.log("Saved to config-generated.json!");
});
