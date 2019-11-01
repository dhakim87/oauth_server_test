/**
 * Module dependencies.
 */
var config = require('./config.json');
var crypto = require('crypto');
var jwtLib = require('jsonwebtoken');
var secureRandom = require('secure-random');
var signingKey = Buffer.from(config.SIGNING_KEY, 'base64');

var generateSalt = function(){
  //Salt recommended to be at least 128 bits.
  return secureRandom(16, {type: 'Buffer'}).toString('base64');
}

var readPepper = function(){
  return config.PW_PEPPER;
}

var hashPassword = function(password, salt, pepper) {
  //May need to use asynchronous version to keep site responsive.
  var hash = crypto.pbkdf2Sync(password, salt + pepper, 100000, 64, 'sha512');
  hash = hash.toString('base64');
  return hash;
}

//postgres://username:password@host:port/database?ssl=false&application_name=name&fallback_application_name=name&client_encoding=encoding
var pg = require('pg-promise')({});
var db = pg(config.DB_CONN);

/*
 * Get access token.
 */

module.exports.getAccessToken = function(bearerToken) {
  return db.query('SELECT access_token, access_token_expires_on, client_id, refresh_token, refresh_token_expires_on, user_id FROM oauth_tokens WHERE access_token = $1', [bearerToken])
    .then(function(result) {
      var token = result.rows[0];

      return {
        accessToken: token.access_token,
        client: {id: token.client_id},
        expires: token.expires,
        user: {id: token.userId.id}, // could be any object
      };
    });
};

/**
 * Get client.
 */

module.exports.getClient = function (clientId, clientSecret) {

  if (clientSecret === null){
    return db.one('SELECT client_id, client_secret, redirect_uri FROM oauth_clients WHERE client_id = $1', [clientId])
      .then(function (row) {
        if (!row)
          return null;
        obj = {
          clientId: row.client_id,
          clientSecret: row.client_secret,
          redirectUris: [row.redirect_uri],
          grants: ['password', 'authorization_code']
        };
        return obj;
      }).catch(function(err){

      });
  }
  else {
    return db.one('SELECT client_id, client_secret, redirect_uri FROM oauth_clients WHERE client_id = $1 AND client_secret = $2', [clientId, clientSecret])
      .then(function(row) {
        if (!row)
          return null;
        return {
          clientId: row.client_id,
          clientSecret: row.client_secret,
          redirectUris: [row.redirect_uri],
          grants: ['password', 'authorization_code'], // the list of OAuth2 grant types that should be allowed
        };
      }).catch(function (err) {

      });
  }
};

/**
 * Get refresh token.
 */

module.exports.getRefreshToken = function *(bearerToken) {
  return db.query('SELECT access_token, access_token_expires_on, client_id, refresh_token, refresh_token_expires_on, user_id FROM oauth_tokens WHERE refresh_token = $1', [bearerToken])
    .then(function(result) {
      return result.rowCount ? result.rows[0] : false;
    });
};

/*
 * Get user.
 */

module.exports.getUser = function(email, password)
{
  return db.one('SELECT id, salt, hash FROM users WHERE email = $1', [email])
    .then(function(row) {
      var hash = hashPassword(password, row.salt, readPepper());
      hash = hash.toString('base64');
      if (hash === row.hash)
        return {id: row.id};
      return null;
    })
    .catch(function(error){

      return null;
    });
};


//Helper function, isn't used by node oauth2
module.exports.getUserById = function(id)
{
  return db.one('select id, email FROM users WHERE id = $1', [id])
    .then(function(row) {
      if (!row)
        return null;
      return {
        id: row.id,
        email: row.email
      }
    })
    .catch(function(error){
      return null;
    })

}

/*
 * Add user.
 */

module.exports.addUser = function(email, password) {
  var salt = generateSalt();
  var pepper = readPepper();
  var hash = hashPassword(password, salt, pepper);

  return db.result(
    'INSERT INTO users(email, salt, hash) VALUES($1,$2,$3)',
    [
      email,
      salt,
      hash
    ]).then(result => {
      return result.rowCount;
    }).catch(error => {
      return null;
    });
}

/**
 * Save token.
 */

module.exports.saveToken = function (token, client, user) {
  return db.result('INSERT INTO oauth_tokens(access_token, access_token_expires_on, client_id, refresh_token, refresh_token_expires_on, user_id) VALUES ($1, $2, $3, $4, $5, $6)', [
    token.accessToken,
    token.accessTokenExpiresAt,
    client.clientId,
    token.refreshToken,
    token.refreshTokenExpiresAt,
    user.id
  ]).then(function(result) {
    if (result.rowCount !== 1)
      return null;
    var t = {}
    t.accessToken = token.accessToken;
    t.accessTokenExpiresAt = token.accessTokenExpiresAt;
    t.refreshToken = token.refreshToken;
    t.refreshTokenExpiresAt = token.refreshTokenExpiresAt;
    t.scope = token.scope;
    t.client = client;
    t.client.id = client.clientId;
    t.user = user;
    return t;
  }).then(function(t){
    //Append id_token
    var claims = {
      iss: "https://oauth-test.ucsd.edu",  // The URL of your service
      sub: user.id,    // The UID of the user in your system
      aud: "PutRESTAPIEndpointHere",
      iat: Date.now() - (1000 * 60 * 5), //Subtract 5 minutes to deal with offset clocks.
      exp: t.accessTokenExpiresAt.getTime(),
    };

    var idToken = jwtLib.sign(claims, signingKey, { algorithm:"HS256"});
    t.id_token = idToken;
    return t;
  }).catch(function (err) {
    return null;
  })
};

/**
 * Get Auth Code.
 */

module.exports.getAuthorizationCode = function(authorizationCode) {
  return db.one('SELECT access_code, exp, client_id, user_id FROM oauth_codes WHERE access_code=$1',
    [authorizationCode]).then(function(row){
      if (!row)
        return null;
      return module.exports.getUserById(row.user_id).then(function(user){
        return module.exports.getClient(row.client_id, null).then(function(client){
          var code = {}
          code.code = row.access_code;
          code.expiresAt = new Date(row.exp);
          //code.redirectUri = ???
          //code.scope = ???
          code.user = user;
          code.client = client;
          return code;
        });
      });
    }).catch(function(err){
      return null;
    });
}

module.exports.revokeAuthorizationCode = function(code){
  return db.result('DELETE FROM oauth_codes WHERE access_code=$1', [code.code])
    .then(function(result) {
      return (result.rowCount === 1);
    })
    .catch(function (err) {
      return false;
    })
}

/**
 * Save Auth Code.
 */

module.exports.saveAuthorizationCode = function (code, client, user) {
  return db.result('INSERT INTO oauth_codes(access_code, exp, client_id, user_id) VALUES($1, $2, $3, $4)',
    [
      code.authorizationCode,
      code.expiresAt,
      client.clientId,
      user.id
    ]).then(function(result) {
      if (result.rowCount === 1)
        return {
          authorizationCode: code.authorizationCode,
          expiresAt: code.expiresAt,
          redirectUri: client.redirectUris[0],
          scope: code.scope,
          client: client,
          user: user
        };
      return null;
    }).catch(function(err) {
      return null;
    });
}
