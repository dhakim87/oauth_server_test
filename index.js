/**
 * Module dependencies.
 */
var bodyParser = require('body-parser');
var express = require('express');

//Use Express Wrapper
var oauthServer = require('express-oauth-server');
//Or not
  // var oauthServer = require('oauth2-server'),
  // Request = OAuth2Server.Request,
  // Response = OAuth2Server.Response;
//

var util = require('util');

// Create an Express application.
var app = express();
app.set('views', "./views");
app.set('view engine', 'ejs');
app.use(express.static("public"));

// Add body parser.
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.get('/', function(req, resp){
  resp.render('babysFirstTemplate');
});

var oauthDb = require('./model');

// Add OAuth server.
app.oauth = new oauthServer({
  model: oauthDb,
  allowExtendedTokenAttributes: true
});

// Post token.
app.post('/oauth/token', app.oauth.token());

// Get authorization.
app.get('/oauth/authorize', function(req, res) {
  // Redirect anonymous users to login page.
  if (!req.app.locals.user) {
    return res.redirect(
      util.format('/login?redirect=%s&client_id=%s&redirect_uri=%s&state=%s&response_type=%s',
        req.route.path,
        req.query.client_id,
        req.query.redirect_uri,
        req.query.state,
        req.query.response_type));
  }

  return res.render('authorize', {
    client_id: req.query.client_id,
    redirect_uri: req.query.redirect_uri
  });
});

// Post authorization.
app.post('/oauth/authorize', function(req, res) {
  // Redirect anonymous users to login page.
  if (!req.app.locals.user) {
    return res.redirect(util.format('/login?client_id=%s&redirect_uri=%s', req.query.client_id, req.query.redirect_uri));
  }

  var currentUser = req.app.locals.user;
  //This is a steaming pile of bullcrap
  //https://github.com/oauthjs/node-oauth2-server/issues/494
  //This library is complete trash, need a different one.
  options = {
    authenticateHandler: {
      handle: (data) => {
        return currentUser;
      }
    }
  }
  app.oauth.authorize(options)(req, res);
});

app.get('/register', function(req, res) {
  return res.render('register', {});
});

//Probably needs a redirect back to whoever told me to register.
app.post('/register', function(req, res) {
  var email = req.body.email;
  var pass = req.body.pass;

  //Send user an email and wait...
  //or just register the user right now.. bleh.

  var promise = oauthDb.addUser(email, pass);
  promise.then(rowCount => {
    if (rowCount === 1)
      return res.redirect('/');
    else
      return res.render('register', {
        error: "Failed To Register: " + email
      });
  })
})

// Get login.
app.get('/login', function(req, res) {
  return res.render('login', {
    redirect: req.query.redirect,
    client_id: req.query.client_id,
    redirect_uri: req.query.redirect_uri,
    state: req.query.state,
    response_type: req.query.response_type
  });
});

// Post login.
app.post('/login', function(req, res) {
  //Good lord, this example doesn't actually do the hardest part.
  var email = req.body.email;
  var password = req.body.pass;

  var promise = oauthDb.getUser(email, password);
  promise.then(function(userObj){
    if (userObj === null) {
      //Incorrect password, or wrong username.
      return res.render('login', {
        redirect: req.query.redirect,
        client_id: req.query.client_id,
        redirect_uri: req.query.redirect_uri,
        state: req.query.state,
        response_type: req.query.response_type,
        error: "Incorrect Email/Password"
      });
    }
    else
    {
      req.app.locals.user = userObj;
      var path = req.query.redirect;
      redirUrl = util.format('%s?client_id=%s&redirect_uri=%s&state=%s&response_type=%s', path, req.query.client_id, req.query.redirect_uri, req.query.state, req.query.response_type);
      return res.redirect(redirUrl);
    }
  });
});

// Start listening for requests.
console.log("listening for requests!");
app.listen(3000);
