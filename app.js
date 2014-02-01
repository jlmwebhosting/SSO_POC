var express = require('express')
  , passport = require('passport')
  , util = require('util')
  , SamlStrategy = require('passport-saml-encrypted').Strategy
  , fs = require('fs')
  , https=require('https')
  , http=require('http');
  

var users = [
 ];

function findByEmail(email, fn) {
  for (var i = 0, len = users.length; i < len; i++) {
    var user = users[i];
    if (user.Email === email) {
      return fn(null, user);
    }
  }
  return fn(null, null);
}


// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.
passport.serializeUser(function(user, done) {
  done(null, user.Email);
});

passport.deserializeUser(function(id, done) {
  findByEmail(id, function (err, user) {
    done(err, user);
  });
});

passport.use(new SamlStrategy(
  {
      path: '/saml/acs',
      entryPoint: 'https://fedpocv1.corp.ebay.com/idp/SSO.saml2',
      issuer: 'https://pdc-main-144272.phx-os1.stratus.dev.ebay.com', // Depends on each project
      protocol: 'https://',
      logging:true,
      callbackUrl:'https://pdc-main-144272.phx-os1.stratus.dev.ebay.com:8443/saml/acs',  //https://hostname/saml/acs
      // Below Configs is mandatory and should have proper values, especially privateCert should be proper
      //eBay SAML cert
      cert:"MIIDjjCCAnagAwIBAgIGAT2JnumBMA0GCSqGSIb3DQEBBQUAMIGHMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTERMA8GA1UEBxMIU2FuIEpvc2UxEjAQBgNVBAoTCWVCYXkgSW5jLjEUMBIGA1UECxMLSVQgU2VydmljZXMxJjAkBgNVBAMTHXNzb3NpZ25mZWRwb2N2MS5jb3JwLmViYXkuY29tMB4XDTEzMDMyMDIxMDUyNVoXDTE1MDMyMDIxMDUyNVowgYcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMREwDwYDVQQHEwhTYW4gSm9zZTESMBAGA1UEChMJZUJheSBJbmMuMRQwEgYDVQQLEwtJVCBTZXJ2aWNlczEmMCQGA1UEAxMdc3Nvc2lnbmZlZHBvY3YxLmNvcnAuZWJheS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCWH7K2M47F957/XqfkW4vMMjuiXbZ3fDUBjT8MOVN6egcBwbFD/qmsrNABWIeKQVR0bmHIyuIgrk+faSFvhFifUrNGEr7oye7tEca86yZiAC+MCwmtydDIHZRvCQM6+NgsNsRH7C8j03Rbg6QtmLOqi6SRcrdkWd3W5dY8cu9+12LMkqfWs6CnxHsijfU+7ewtWoWRX6MGAL2V/L1j0zu4tfOF1hJFWUrpgc2IdUeA5dE1eRhTQGZqehPhkQGBEObrOJJKlf8YNvRwZry2UJmfr0C0VZmPgMy2xs6xQeHajEBr0mRhSLc8D+yxlfrmZWWDK/tgTWN1ISupYFyjugifAgMBAAEwDQYJKoZIhvcNAQEFBQADggEBAAnadAELq7fpjImlzFbOHOan9Oo5RtCwXSdbksx91UOkcSO3HIAWgHC3enRh94Beb7x2tOmRO54RomtJGE+DB/S06UnEkJ2JMDIMGcqxIntHmBqp6c3dn7GtBJ6WO6d5ds6KpwMn4xmmBMSDdknblxlOUzMq/KMM0WqVxRX1Lof4oryNMMhrii7AOMs4p/9YczKRtsX7YQi93MpTvkvZPjlCuWWRAB42Z7FUiR5CTGVv8w6GMZt4MItQOHKEEOmL6olo0QILibmEHzdgiSl2c9SltdYEymT11/Ex+TN5jC+CAZZlm7LB7cB9cGYIuzJl2PVWn3oYi3c7rPrwIqooxkU=",
      //my private cert
      privateCert: fs.readFileSync('./ssl/privkey.pem', 'utf-8'),  //need to generate key using openssl and put it in server
      encryptedSAML:true,
      identifierFormat:"urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
},
  function(profile, done) {
    console.log("Auth with", profile);
    if (!profile.Email) {
      return done(new Error("No email found"), null);
    }
    // asynchronous verification, for effect...
    process.nextTick(function () {
      findByEmail(profile.Email, function(err, user) {
        if (err) {
          return done(err);
        }
        if (!user) {
          // "Auto-registration"
            console.log("Register")
          users.push(profile);
          console.log(JSON.stringify(users))
          return done(null, profile);
        }
        return done(null, user);
      })
    });
  }
));

var options = {
    key: fs.readFileSync(__dirname + '/ssl/privkey.pem'),
    cert: fs.readFileSync(__dirname + '/ssl/cacert.pem')
};



var app = express();

// configure Express
app.configure(function() {
  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
  app.use(express.logger());
  app.use(express.cookieParser());
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.session({ secret: 'keyboard cat' }));
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(app.router);
  app.use(express.static(__dirname + '/public'));
});


app.get('/',ensureAuthenticated, function(req, res){
    console.log(req.user);
  res.render('index', { user: req.user });
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

app.get('/login',
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);

app.post('/login/callback',
  passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
  function(req, res) {
    res.redirect('/');
  }
);

app.post('/saml/acs',
   passport.authenticate('saml', { failureRedirect: '/', failureFlash: true }),
    function(req, res) {
        res.redirect('/');
    }
);

app.get('/logout', function(req, res){
  users.length=0;
  req.logout();
  res.redirect('/');
});

//START : This configuration needed only for enabiling SSL to Integrating SSO in Dev


https.createServer(options, app).listen(8443, function(){
    console.log("ssl started on port " + 8443);
});

/*
var port = process.env.PORT || 8000

http.createServer(app).listen(port,function(){
    console.log("Server listening in http://localhost:"+port);
})
//*/
//END : This configuration only needed only for Integrating SSO in Dev

//Uncomment this if you are not using https in node js.
/*app.listen(port, function () {
  console.log("Server listening in http://localhost:4567");
});*/

// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login')
}
