'use strict';

/**
 * OAuth/Passport.js/Mongoose Implementation middleware and plugin.
 * You can use this Plugin to annotate your own Mongoose Model with a
 * RequestToken method. This method will then handle creating your
 * Request Token/Secret pair and responding to the requester with the
 * appropriate OAuth values be them errors or valid Tokens.
 *
 * @options
 *      oauth if true you must pass an instance of passport.js in order
 *      for OAuthentication to work. If false then a cosumerkey and consumersecret
 *      will be created on your model so that you can use them outside of Passport.js
 *      passport should be your applications instance of Passport.js
 *
 * YourModelSchema.plugin(MongooseOauthPassport.plugin, {
 * oauth:true,
 * passport:require('passport')
 * }
 */
exports = module.exports = function Plugin(schema, options) {

    var _ = require('lodash');
    options = _.defaults(options || {}, {
        requestTokenExpire: false,
        requestTokenExpires: '10m',
        oauth: false
    });

    //-------------------------------------------------------------------------
    //
    // Public Methods
    //
    //-------------------------------------------------------------------------

    if (options.oauth) {
        /**
         * Request a Authorization token
         * @param req
         * @param res
         * @param parse
         * @param next
         */
        schema.statics.requestToken = function (req, res, parse, next) {
            requestToken(this, req, res, parse, next);
        };

        schema.statics.authorizeUser = function(req, res, parse, next){
            authorizeUser(this, req, res, parse, next);
        };

        schema.statics.accessToken = function(req, res, next){
            accessToken(this, req, res, next);
        };
    }

    //-------------------------------------------------------------------------
    //
    // Private Properties
    //
    //-------------------------------------------------------------------------

    var log = require('nodelogger')('MongooseOAuthRequestToken');
    if ((options.oauth && !options.passport)) {
        throw log.error('You must provide an instance of Passport.js in order for MongooseAuthOauth to work correctly with OAuth');
    }

    if (!options.tableName) {
        throw log.error('You must specify a tableName in the options when creating a MongooseAuthOAuth');
    }

    var passport = options.passport;
    var Token = require('MongooseToken');
    var oauth = require('oauthorize').createServer();
    var ConsumerStrategy = require('passport-http-oauth').ConsumerStrategy;
//    var TokenStrategy = require('passport-http-oauth').TokenStrategy;

//    var TYPE = options.tableName.toLowerCase();
    var upperTableName = options.tableName.slice(0, 1).toUpperCase() + options.tableName.slice(1);
    var lowerTableName = options.tableName.slice(0, 1).toLowerCase() + options.tableName.slice(1);
    var REQUEST_TOKEN = lowerTableName + 'RequestToken';
    var CREATE_REQUEST_TOKEN = 'create' + upperTableName + 'RequestToken';
    var FIND_REQUEST_TOKEN = 'find' + upperTableName + 'RequestTokenByKey';
    var FIND_CONSUMER_BY_KEY = 'findBy' + upperTableName + 'ConsumerKey';
    var FIND_CONSUMER_TOKEN = 'find' + upperTableName + 'Consumer';
//    var extension;
    var strategy;

    oauth.serializeClient(function (consumer, done) {
        log.debug('Consumer is ', consumer);
        return done(null, consumer.id);
    });

    oauth.deserializeClient(function (id, done) {
        log.debug('Deserialize Consumer', id);
        done(null, id);
    });

    /**
     * Create a request token table this table will expire so that we do not allow for
     * long requests.
     */
    schema.plugin(Token.plugin, {
        tableName: REQUEST_TOKEN,
        expire: options.requestTokenExpire,
        expires: options.requestTokenExpires,
        unique:false,
        schema:{
            callback:String
        }
    });

    schema.plugin(Token.plugin, {
        tableName: upperTableName + 'Consumer'
    });

    //-------------------------------------------------------------------------
    //
    // Private Methods
    //
    //-------------------------------------------------------------------------

    function requestToken(self, req, res, parse, next) {
        useStrategy(self);
        if (typeof next !== 'function' && typeof parse === 'function'){
            next = parse;
            parse = null;
        }
        passport.authenticate('consumer', {session: false})(req, res, function () {
            var token = oauth.requestToken(parse, function (consumer, callback, params, done) {
                consumer[CREATE_REQUEST_TOKEN]({callback:callback}, function (err, token) {
                    if (err) {
                        log.error('Error retrieving RequestToken Model', err);
                        done(err, false);
                    } else {
                        log.debug('Created RequestToken:token', token);
                        done(null, token.key, token.secret, params);
                    }
                });
            });

            token(req, res, function (err, result) {
                log.warn('consumer:request_token', err, result);
                next(err, result);
            });
        });
    }

    function authorizeUser(Model, req, res, parse, next){
        useStrategy(Model);
        if (typeof next !== 'function' && typeof parse === 'function'){
            next = parse;
            parse = null;
        }
        var auth = oauth.userAuthorization(parse, function(requestToken, params, done){
            Model[FIND_REQUEST_TOKEN](requestToken, function(err, token){
                if(err){
                    return done(err);
                }
                if (!token) {
                    return done(null, false);
                }
                Model.findOne({_id: token.modelId}, function(err, consumer){
                    if(err){
                        return done(err);
                    }
                    if(!consumer){
                        return done(null, false);
                    }
                    done(null, consumer, token.callbackURL, params);
                });
            });
        });
        auth(req, res, function (err, result) {
            log.debug('consumer:user_authorization', err, result, req.oauth);
            next(err, result);
        });
    }

    /**
     * server.userAuthorization(function(requestToken, done) {
    db.requestTokens.find(requestToken, function(err, token) {
      if (err) { return done(err); }
      db.clients.find(token.clientID, function(err, client) {
        if (err) { return done(err); }
        return done(null, client, token.callbackURL);
      });
    });
  }),
     * @param self
     * @param req
     * @param res
     * @param next
     */
    function accessToken(self, req, res, next){
        useStrategy(self);
        passport.authenticate('consumer', {session:false})(req, res, function(){
            oauth.accessToken(function(requestToken, verifier, info, done){
                console.log('Access Token', requestToken, verifier, info);
                done(null, true);
            }, function(consumer, requestToken, info, done){
                console.log('Consumer', consumer, requestToken, info);
                done(null, '1234', '12345');
            })(req, res, function(err, result){
                log.warn('consumer:access_token', err, result);
                next(err, result);
            });
        });
    }

    /**
     * server.accessToken(
     function(requestToken, verifier, info, done) {
      if (verifier != info.verifier) { return done(null, false); }
      return done(null, true);
    },
     function(client, requestToken, info, done) {
      if (!info.approved) { return done(null, false); }
      if (client.id !== info.clientID) { return done(null, false); }

      var token = utils.uid(16)
        , secret = utils.uid(64)

      db.accessTokens.save(token, secret, info.userID, info.clientID, function(err) {
        if (err) { return done(err); }
        return done(null, token, secret);
      });
    }
     ),
     server.errorHandler()
     * @param Model
     */

    function useStrategy(Model) {
        if (!strategy) {
            passport.use('consumer', new ConsumerStrategy(
                validateRequestToken(Model),
                validateAccessToken(Model),
                function (timestamp, nonce, done) {
                    console.log('Validating NONCE HERE');
                    // validate the timestamp and nonce as necessary
                    done(null, true);
                }
            ));
        }
    }

    function validateRequestToken(Model) {
        return function(consumerKey, done){
            Model[FIND_CONSUMER_BY_KEY](consumerKey, function (err, consumer) {
                if (err) {
                    log.error('Error finding consumer', err);
                    return done(null, false);
                }
                if (!consumer) {
                    return done(null, false);
                }
                consumer[FIND_CONSUMER_TOKEN](function (err, tokens) {
                    if (err) {
                        log.error('Error finding consumer secret', err);
                    }
                    var token = tokens[0];
                    if(!token){
                        return done(null, false);
                    }
                    done(err, consumer, token.secret);
                });
            });
        };
    }

    function validateAccessToken(Model){
        return function (requestToken, done) {
            Model[FIND_REQUEST_TOKEN](requestToken, function (err, token) {
                if(err){
                    return done(err);
                }
                if(!token){
                    return done(null, false);
                }
                done(null, token.secret, token);
            });
        };
    }

//    function getExtension(db){
//        if(!extension){
//            //Create temporary model so we can get a hold of a valid Schema object.
//            var extensionSchema = db.model('____' + TYPE + '____', {}).schema;
//            extensionSchema.statics.TYPE = TYPE;
//
//            var extensionOptions = {
//                type: {type: String, 'default': TYPE},
//                modelId: String
//            };
//        }
//    }

};
