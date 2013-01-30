//
// Copyright (c) 2011 Mashery, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// 'Software'), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

//
// Module dependencies
//
var express     = require('express'),
    util        = require('util'),
    fs          = require('fs'),
    OAuth       = require('oauth').OAuth2,
    query       = require('querystring'),
    url         = require('url'),
    http        = require('http'),
    https       = require('https'),
    crypto      = require('crypto'),
    redis       = require('redis'),
    RedisStore  = require('connect-redis')(express);

// Configuration
try {
    var configJSON = fs.readFileSync(__dirname + "/config.json");
    var config = JSON.parse(configJSON.toString());
} catch(e) {
    console.error("File config.json not found or is invalid.  Try: `cp config.json.sample config.json`");
    process.exit(1);
}

//
// Redis connection
//
var defaultDB = '0';
var db;

if (process.env.REDISTOGO_URL) {
    var rtg   = require("url").parse(process.env.REDISTOGO_URL);
    db = require("redis").createClient(rtg.port, rtg.hostname);
    db.auth(rtg.auth.split(":")[1]);
} else {
    db = redis.createClient(config.redis.port, config.redis.host);
    db.auth(config.redis.password);
}

db.on("error", function(err) {
    if (config.debug) {
         console.log("Error " + err);
    }
});

//
// Load API Configs
//
var apisConfig;
var apiCache = {};
fs.readFile(__dirname +'/public/data/apiconfig.json', 'utf-8', function(err, data) {
    if (err) throw err;
    apisConfig = JSON.parse(data);
    if (config.debug) {
         console.log(util.inspect(apisConfig));
    }
    getConfigs = function(){
        if (apisConfig) {
            Object.keys(apisConfig).forEach(function(aconfig) {
                cfg = apisConfig[aconfig]
                if (cfg.remoteConfigUrl) {
                    var options = url.parse(cfg.remoteConfigUrl)
                    
                    var remoteApiCall = http.request(options, function(response) {
                        var str = '';

                        response.on('data', function (chunk) {
                            str += chunk;
                        });

                        response.on('end', function () {
                            try {
                                apiCache[aconfig] = JSON.parse(str)
                            } catch(e) {
                                console.log("Load of " + aconfig + " failed.")
                            }
                        });
                    });
                    remoteApiCall.end();
                } else {
                    try {
                        apiCache[aconfig] = JSON.parse(fs.readFileSync(__dirname + '/public/data/' + aconfig + '.json'));
                    } catch(e) {
                        console.log("Load of " + aconfig + " failed.")
                    }
                }
            });
        }
    }
    getConfigs();
    setInterval(getConfigs,15 * 60 * 1000); //Refresh every 15 min.
});

if (config.auth) {
    auth = express.basicAuth(process.env.AUTH_USERNAME || '',process.env.AUTH_PASSWORD || '');
    var app = module.exports = express.createServer(auth);
} else {
    var app = module.exports = express.createServer();
}

if (process.env.REDISTOGO_URL) {
    var rtg   = require("url").parse(process.env.REDISTOGO_URL);
    config.redis.host = rtg.hostname;
    config.redis.port = rtg.port;
    config.redis.password = rtg.auth.split(":")[1];
}

app.configure(function() {
    app.set('views', __dirname + '/views');
    app.set('view engine', 'jade');
    app.use(express.logger());
    app.use(express.bodyParser());
    app.use(express.methodOverride());
    app.use(express.cookieParser());
    app.use(express.session({
        secret: config.sessionSecret,
        store:  new RedisStore({
            'host':   config.redis.host,
            'port':   config.redis.port,
            'pass':   config.redis.password,
            'maxAge': 1209600000
        })
    }));

    app.use(app.router);

    app.use(express.static(__dirname + '/public'));
});

app.configure('development', function() {
    app.use(express.errorHandler({ dumpExceptions: true, showStack: true }));
});

app.configure('production', function() {
    app.use(express.errorHandler());
});

//
// Middleware
//
function oauth(req, res, next) {
    console.log('OAuth process started');
    var apiName = req.body.apiName,
        apiConfig = apisConfig[apiName];

    if (apiConfig.oauth) {
        var clientId = req.body.clientId || req.body.key,
            refererURL = url.parse(req.headers.referer),
            callbackURL = refererURL.protocol + '//' + refererURL.host + '/authSuccess/' + apiName,
            clientSecret = req.body.clientSecret || req.body.secret
        if (config.debug) {
            console.log('Method security: ' + req.body.oauth);
            console.log('Session authed: ' + req.session[apiName]);
            console.log('clientId: ' + clientId);
            console.log('clientSecret: ' + clientSecret);
        };
        // Check if the API even uses OAuth, then if the method requires oauth, then if the session is not authed
        if (req.body.oauth == 'authrequired' && (!req.session[apiName] || !req.session[apiName].authed) ) {
            if (config.debug) {
                console.log('req.session: ' + util.inspect(req.session));
                console.log('headers: ' + util.inspect(req.headers));
                console.log('sessionID: ' + util.inspect(req.sessionID));
            };
            var key = req.sessionID + ':' + apiName;

            db.set(key + ':clientId', clientId, redis.print);
            db.set(key + ':clientSecret', clientSecret, redis.print);
            // Set expiration to same as session
            db.expire(key + ':clientId', 1209600000);
            db.expire(key + ':clientSecret', 1209600000);

            res.send({ 'signin': apiConfig.oauth.baseURL + apiConfig.oauth.authorizeURL + '?response_type=code&client_id=' + clientId + '&redirect_uri=' + callbackURL  });
        } else {
            next();
        }
    } else {
        next();
    }

}

//
// OAuth Success!
//
function oauthSuccess(req, res, next) {
    var clientId,
        clientSecret,
        apiName = req.params.api,
        apiConfig = apisConfig[apiName],
        key = req.sessionID + ':' + apiName; // Unique key using the sessionID and API name to store tokens and secrets

    if (config.debug) {
        console.log('apiName: ' + apiName);
        console.log('key: ' + key);
        console.log(util.inspect(req.params));
    };

    db.mget([
        key + ':clientId',
        key + ':clientSecret'
    ], function(err, result) {
        if (err) {
            console.log(util.inspect(err));
        }
        clientId = result[0],
        clientSecret = result[1];

        var oa = new OAuth(clientId,
                            clientSecret,
                            apiConfig.oauth.baseURL,
                            apiConfig.oauth.authorizeURL,
                            apiConfig.oauth.accessTokenURL
                            );

        req.query['grant_type']='authorization_code'

        oa.getOAuthAccessToken(req.query.code, req.query, function(error, access_token, refresh_token, results) {
            if (error) {
                res.send("Error getting OAuth access token : " + util.inspect(error) + "["+access_token+"]"+ "["+refresh_token+"]"+ "["+util.inspect(results)+"]", 500);
            } else {
                if (config.debug) {
                    console.log('results: ' + util.inspect(results));
                };
                db.mset([key + ':accessToken', access_token, key + ':refreshToken', refresh_token], function(err, results2) {
                        req.session[apiName] = {};
                        req.session[apiName].authed = true;
                        if (config.debug) {
                            console.log('session[apiName].authed: ' + util.inspect(req.session));
                        };
                        next();
                });
            }
        });

    });
}

//
// processRequest - handles API call
//
function processRequest(req, res, next) {
    if (config.debug) {
        console.log(util.inspect(req.body, null, 3));
    };

    var reqQuery = req.body,
        params = reqQuery.params || {},
        methodURL = reqQuery.methodUri,
        httpMethod = reqQuery.httpMethod,
        apiKey = reqQuery.apiKey,
        apiSecret = reqQuery.apiSecret,
        apiName = reqQuery.apiName
        apiConfig = apisConfig[apiName],
        key = req.sessionID + ':' + apiName;

    // Replace placeholders in the methodURL with matching params
    for (var param in params) {
        if (params.hasOwnProperty(param)) {
            if (params[param] !== '') {
                // URL params are prepended with ":"
                var regx = new RegExp(':' + param);

                // If the param is actually a part of the URL, put it in the URL and remove the param
                if (!!regx.test(methodURL)) {
                    methodURL = methodURL.replace(regx, params[param]);
                    delete params[param]
                }
            } else {
                delete params[param]; // Delete blank params
            }
        }
    }

    var baseHostInfo = apiConfig.baseURL.split(':');
    var baseHostUrl = baseHostInfo[0],
        baseHostPort = (baseHostInfo.length > 1) ? baseHostInfo[1] : "";

    var paramString = query.stringify(params),
        privateReqURL = apiConfig.protocol + '://' + apiConfig.baseURL + apiConfig.privatePath + methodURL + ((paramString.length > 0) ? '?' + paramString : ""),
        options = {
            headers: {},
            protocol: apiConfig.protocol + ':',
            host: baseHostUrl,
            port: baseHostPort,
            method: httpMethod,
            path: apiConfig.publicPath + methodURL// + ((paramString.length > 0) ? '?' + paramString : "")
        };

    if (apiConfig.headers) {
        if (config.debug) {
            console.log('Setting default headers');
        }

        for (var key in apiConfig.headers) {
            if (!options.headers[key]) {
                if (config.debug) {
                    console.log('Setting header: ' + key + ':' + apiConfig.headers[key]);
                }
                options.headers[key] = apiConfig.headers[key];
            }
        }
    }

    if (['POST','DELETE','PUT'].indexOf(httpMethod) !== -1) {
        var requestBody = query.stringify(params);
    }

    if (apiConfig.oauth) {
        console.log('Using OAuth');

        if (reqQuery.oauth == 'authrequired' || (req.session[apiName] && req.session[apiName].authed)) {

            db.mget([key + ':clientId',
                     key + ':clientSecret',
                     key + ':accessToken',
                     key + ':refreshToken'
                ],
                function(err, results) {

                    var clientKey = (typeof reqQuery.key == "undefined" || reqQuery.key == "undefined")?results[0]:reqQuery.key,
                        clientSecret = (typeof reqQuery.secret == "undefined" || reqQuery.secret == "undefined")?results[1]:reqQuery.secret,
                        accessToken = results[2],
                        refreshToken = results[3];

                    var oa = new OAuth(clientKey || null,
                                       clientSecret || null,
                                        apiConfig.oauth.baseURL,
                                        apiConfig.oauth.authorizeURL,
                                        apiConfig.oauth.accessTokenURL)
                    if (config.debug) {
                        console.log('Access token: ' + accessToken);
                        console.log('Refresh token: ' + refreshToken);
                        console.log('key: ' + key);
                    };

                    oa._request(options.method, privateReqURL, options.headers, requestBody, accessToken, function (error, data, response) {
                        req.call = privateReqURL;

                        // console.log(util.inspect(response));
                        if (error) {
                            console.log('Got error: ' + util.inspect(error));

                            if (error.data == 'Server Error' || error.data == '') {
                                req.result = 'Server Error';
                            } else {
                                req.result = error.data;
                            }

                            res.statusCode = error.statusCode

                            next();
                        } else {
                            req.resultHeaders = response.headers;
                            req.result = JSON.parse(data);
                            if (config.debug) {
                                console.log(req.result);
                            }
                            next();
                        }
                    });
                }
            );
        } else {
            // API uses OAuth, but this call doesn't require auth and the user isn't already authed, so just call it.
            unsecuredCall();
        }
    } else {
        // API does not use authentication
        unsecuredCall();
    }

    // Unsecured API Call helper
    function unsecuredCall() {
        console.log('Unsecured Call');

        if (['POST','PUT','DELETE'].indexOf(httpMethod) === -1) {
            options.path += ((paramString.length > 0) ? '?' + paramString : "");
        }

        // Add API Key to params, if any.
        if (apiKey != '' && apiKey != 'undefined' && apiKey != undefined) {
            if (options.path.indexOf('?') !== -1) {
                options.path += '&';
            }
            else {
                options.path += '?';
            }
            options.path += apiConfig.keyParam + '=' + apiKey;
        }

        // Perform signature routine, if any.
        if (apiConfig.signature) {
            if (apiConfig.signature.type == 'signed_md5') {
                // Add signature parameter
                var timeStamp = Math.round(new Date().getTime()/1000);
                var sig = crypto.createHash('md5').update('' + apiKey + timeStamp + '').digest(apiConfig.apiSecret);
                options.path += '&' + apiConfig.signature.sigParam + '=' + sig;
            }
            else if (apiConfig.signature.type == 'signed_sha256') { // sha256(key+secret+epoch)
                // Add signature parameter
                var timeStamp = Math.round(new Date().getTime()/1000);
                var sig = crypto.createHash('sha256').update('' + apiKey + timeStamp + '').digest(apiConfig.apiSecret);
                options.path += '&' + apiConfig.signature.sigParam + '=' + sig;
            }
        }

        // Setup headers, if any
        if (reqQuery.headerNames && reqQuery.headerNames.length > 0) {
            if (config.debug) {
                console.log('Setting headers');
            };
            var headers = {};

            for (var x = 0, len = reqQuery.headerNames.length; x < len; x++) {
                if (config.debug) {
                  console.log('Setting header: ' + reqQuery.headerNames[x] + ':' + reqQuery.headerValues[x]);
                };
                if (reqQuery.headerNames[x] != '') {
                    headers[reqQuery.headerNames[x]] = reqQuery.headerValues[x];
                }
            }

            options.headers = headers;
        }

        // Set api default headers, if any
        if (config.headers) {
            if (config.debug) {
                console.log('Setting default headers');
            }

            for (var key in config.headers) {
                if (!options.headers[key]) {
                    if (config.debug) {
                        console.log('Setting header: ' + key + ':' + config.headers[key]);
                    }
                    options.headers[key] = config.headers[key];
                }
            }
        }

        if (!options.headers['Content-Length']) {
            if (requestBody) {
                options.headers['Content-Length'] = requestBody.length;
            }
            else {
                options.headers['Content-Length'] = 0;
            }
        }

        if (requestBody) {
            options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }

        if (config.debug) {
            console.log(util.inspect(options));
        };

        var doRequest;
        if (options.protocol === 'https' || options.protocol === 'https:') {
            console.log('Protocol: HTTPS');
            options.protocol = 'https:'
            doRequest = https.request;
        } else {
            console.log('Protocol: HTTP');
            doRequest = http.request;
        }

        // API Call. response is the response from the API, res is the response we will send back to the user.
        var apiCall = doRequest(options, function(response) {
            response.setEncoding('utf-8');

            if (config.debug) {
                console.log('HEADERS: ' + JSON.stringify(response.headers));
                console.log('STATUS CODE: ' + response.statusCode);
            };

            res.statusCode = response.statusCode;

            var body = '';

            response.on('data', function(data) {
                body += data;
            })

            response.on('end', function() {
                delete options.agent;

                var responseContentType = response.headers['content-type'];

                switch (true) {
                    case /application\/javascript/.test(responseContentType):
                    case /application\/json/.test(responseContentType):
                        console.log(util.inspect(body));
                        // body = JSON.parse(body);
                        break;
                    case /application\/xml/.test(responseContentType):
                    case /text\/xml/.test(responseContentType):
                    default:
                }

                // Set Headers and Call
                req.resultHeaders = response.headers;
                req.call = url.parse(options.host + options.path);
                req.call = url.format(req.call);

                // Response body
                req.result = body;
                if (config.debug) {
                    console.log(util.inspect(body));
                }

                next();
            })
        }).on('error', function(e) {
            if (config.debug) {
                console.log('HEADERS: ' + JSON.stringify(res.headers));
                console.log("Got error: " + e.message);
                console.log("Error: " + util.inspect(e));
            };
        });

        if (requestBody) {
            apiCall.end(requestBody, 'utf-8');
        }
        else {
            apiCall.end();
        }
    }
}


// Dynamic Helpers
// Passes variables to the view
app.dynamicHelpers({
    session: function(req, res) {
    // If api wasn't passed in as a parameter, check the path to see if it's there
        if (!req.params.api) {
            pathName = req.url.replace('/','');
            // Is it a valid API - if there's a config file we can assume so
            fs.stat(__dirname + '/public/data/' + pathName + '.json', function (error, stats) {
                if (stats) {
                    req.params.api = pathName;
                }
            });
        }       
        req.session['authed'] = false
        // If the cookie says we're authed for this particular API, set the session to authed as well
        if (req.params.api && req.session[req.params.api] && req.session[req.params.api]['authed']) {
            req.session['authed'] = true;
        }

        return req.session;
    },
    apiInfo: function(req, res) {
        if (req.params.api) {
            return apisConfig[req.params.api];
        } else {
            return apisConfig;
        }
    },
    apiName: function(req, res) {
        if (req.params.api) {
            return req.params.api;
        }
    },
    apiDefinition: function(req, res) {
        if (req.params.api) {
            return apiCache[req.params.api];
        }
    }
})


//
// Routes
//
app.get('/', function(req, res) {
    // Redirect to the first api in apiconfig
    //var api;
    //for (var key in apisConfig) {
    //    api = key;
    //}
    //res.redirect('/' + api);
     res.render('listAPIs', {
         title: config.title
     });
});

// Process the API request
app.post('/processReq', oauth, processRequest, function(req, res) {
    var result = {
        headers: req.resultHeaders,
        response: req.result,
        call: req.call,
        code: req.res.statusCode
    };

    res.send(result);
});

// Just auth
app.all('/auth', oauth);

// OAuth callback page, closes the window immediately after storing access token/secret
app.get('/authSuccess/:api', oauthSuccess, function(req, res) {
    res.render('authSuccess', {
        title: 'OAuth Successful'
    });
});

app.post('/upload', function(req, res) {
  console.log(req.body.user);
  res.redirect('back');
});

// API shortname, all lowercase
app.get('/:api([^\.]+)', function(req, res) {
    req.params.api=req.params.api.replace(/\/$/,'');
    res.render('api');
});

// Only listen on $ node app.js

if (!module.parent) {
    var port = process.env.PORT || config.port;
    app.listen(port);
    console.log("Express server listening on port %d", app.address().port);
}
