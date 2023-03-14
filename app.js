//. app.js

var express = require( 'express' ),
    bodyParser = require( 'body-parser' ),
    fs = require( 'fs' ),
    ejs = require( 'ejs' ),
    jsonwebtoken = require( 'jsonwebtoken' ),
    session = require( 'express-session' ),
    { v4: uuidv4 } = require( 'uuid' ),
    app = express();

require( 'dotenv' ).config();


app.use( bodyParser.urlencoded( { extended: true } ) );
app.use( bodyParser.json() );
app.use( express.Router() );

app.set( 'views', __dirname + '/views' );
app.set( 'view engine', 'ejs' );

//. env values
var settings_auth0_callback_url = 'AUTH0_CALLBACK_URL' in process.env ? process.env.AUTH0_CALLBACK_URL : ''; 
var settings_auth0_client_id = 'AUTH0_CLIENT_ID' in process.env ? process.env.AUTH0_CLIENT_ID : ''; 
var settings_auth0_client_secret = 'AUTH0_CLIENT_SECRET' in process.env ? process.env.AUTH0_CLIENT_SECRET : ''; 
var settings_auth0_domain = 'AUTH0_DOMAIN' in process.env ? process.env.AUTH0_DOMAIN : ''; 
var settings_auth0_management_client_id = 'AUTH0_MANAGEMENT_CLIENT_ID' in process.env ? process.env.AUTH0_MANAGEMENT_CLIENT_ID : ''; 
var settings_auth0_management_client_secret = 'AUTH0_MANAGEMENT_CLIENT_SECRET' in process.env ? process.env.AUTH0_MANAGEMENT_CLIENT_SECRET : ''; 

//. Auth0 Management API
var ManagementClient = require( 'auth0' ).ManagementClient;
var auth0 = new ManagementClient({
  domain: settings_auth0_domain,
  clientId: settings_auth0_management_client_id,
  clientSecret: settings_auth0_management_client_secret,
  scope: 'create:users read:users update:users'
});

//. Auth0
var passport = require( 'passport' );
var Auth0Strategy = require( 'passport-auth0' );
var strategy = new Auth0Strategy({
  domain: settings_auth0_domain,
  clientID: settings_auth0_client_id,
  clientSecret: settings_auth0_client_secret,
  callbackURL: settings_auth0_callback_url
}, async function( accessToken, refreshToken, extraParams, profile, done ){
  //console.log( accessToken, refreshToken, extraParams, profile );
  profile.idToken = extraParams.id_token;
  //await setUserMeta( profile.id, 'nft', 1 );
  var r = await getUserMeta( profile.id, 'nft' );
  if( r && r.status ){
    //. profile.metadata.xxx で判断できそう
    profile.metadata = { nft: r.nft };
  }
  return done( null, profile );
});
passport.use( strategy );

passport.serializeUser( function( user, done ){
  done( null, user );
});
passport.deserializeUser( function( user, done ){
  done( null, user );
});

//. Session
var sess = {
  secret: 'Auth0CustomAttr',
  cookie: {
    path: '/',
    maxAge: (3 * 60 * 1000)  //. 3min
  },
  resave: false,
  saveUninitialized: true
};
app.use( session( sess ) );
app.use( passport.initialize() );
app.use( passport.session() );

app.use( function( req, res, next ){
  if( req && req.query && req.query.error ){
    console.log( req.query.error );
  }
  if( req && req.query && req.query.error_description ){
    console.log( req.query.error_description );
  }
  next();
});


//. login
app.get( '/auth0/login', passport.authenticate( 'auth0', {
  scope: 'openid profile email',
  successRedirect: '/',
  failureRedirect: '/auth0/login'
}, function( req, res ){
  res.redirect( '/' );
}));

//. logout
app.get( '/auth0/logout', function( req, res, next ){
  req.logout( function( err ){
    if( err ){ return next( err ); }
    res.redirect( '/' );
  });
});

app.get( '/auth0/callback', async function( req, res, next ){
  passport.authenticate( 'auth0', function( err, user ){
    if( err ) return next( err );
    if( !user ) return res.redirect( '/auth0/login' );

    req.logIn( user, function( err ){
      if( err ) return next( err );
      res.redirect( '/' );
    })
  })( req, res, next );
});

app.get( '/', async function( req, res ){
  var user = null;

  if( req.user ){ 
    var user = { id: req.user.id, name: req.user.nickname, email: req.user.displayName, image_url: req.user.picture };
    if( req.user.metadata ){
      user.metadata = req.user.metadata;
    }
  }
  res.render( 'index', { user: user } );
});

async function getUserById( user_id ){
  return new Promise( async ( resolve, reject ) => {
    if( auth0 ){
      var params = { id: user_id };

      auth0.getUser( params, function( err, user ){
        if( err ){
          console.log( { err } );
          resolve( { status: false, error: err } );
        }else{
          //. メタデータは取れるっぽい
          //console.log( { user } );
          resolve( { status: true, user: user } );
        }
      });
    }else{
      resolve( { status: false, error: 'no management credentials provided.' } );
    }
  });
}

async function getUserMeta( user_id, name ){
  return new Promise( async ( resolve, reject ) => {
    if( auth0 ){
      var params = { id: user_id };

      auth0.getUser( params, function( err, user ){
        if( err ){
          console.log( { err } );
          resolve( { status: false, error: err } );
        }else{
          if( user.user_metadata ){
            if( name ){
              var value = null;
              if( user.user_metadata[name] ){
                value = user.user_metadata[name];
              }
  
              var r = { status: true };
              r[name] = value;
  
              resolve( r );
            }else{
              resolve( { status: false, error: 'no user_metadata retrieved.' } );
            }
          }else{
            resolve( { status: false, error: 'name parameter needed.' } );
          }
        }
      });
    }else{
      resolve( { status: false, error: 'no management credentials provided.' } );
    }
  });
}

async function setUserMeta( user_id, name, value ){
  return new Promise( async ( resolve, reject ) => {
    if( auth0 ){
      var params = { id: user_id };
      var metadata = {};
      if( name ){ metadata[name] = value; }

      auth0.users.updateUserMetadata( params, metadata, function( err, user ){
        if( err ){
          console.log( { err } );
          resolve( { status: false, error: err } );
        }else{
          //console.log( { user } );
          resolve( { status: true, user: user } );
        }
      });
    }else{
      resolve( { status: false, error: 'no management credentials provided.' } );
    }
  });
}



var port = process.env.PORT || 8080;
app.listen( port );
console.log( "server starting on " + port + " ..." );
