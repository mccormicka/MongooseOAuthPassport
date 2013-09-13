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
exports = module.exports = function MongooseAuthOauth(schema, options) {

    var _ = require('lodash');
    options = _.defaults(options || {}, {
        requestTokenExpire: true,
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
         * @param next
         * @param parse
         */
        schema.statics.requestToken = function (req, res, next, parse) {
            var self = this;
            useStrategy(self);
            passport.authenticate('consumer', {session: false})(req, res, function () {
                oauth.requestToken(parse, function (client, callback, params, done) {
                    client[CREATE_REQUEST_TOKEN](function (err, token) {
                        if (err) {
                            log.error('Error retrieving RequestToken Model', err);
                            done(err);
                        } else {
                            log.debug('Created RequestToken:token', token);
                            done(null, token.key, token.secret, params);
                        }
                    });
                })(req, res, function (err, result) {
                    log.debug('consumer:request_token', err, result);
                    next(err, result);
                });
            });
        };
    }

    //-------------------------------------------------------------------------
    //
    // Private Methods
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

    var TYPE = options.tableName.toLowerCase();
    var upperTableName = options.tableName.slice(0, 1).toUpperCase() + options.tableName.slice(1);
    var lowerTableName = options.tableName.slice(0, 1).toLowerCase() + options.tableName.slice(1);
    var REQUEST_TOKEN = lowerTableName + 'RequestToken';
    var CREATE_REQUEST_TOKEN = 'create' + upperTableName + 'RequestToken';
    var FIND_CONSUMER_BY_KEY = 'findBy' + upperTableName + 'ConsumerKey';
    var FIND_CONSUMER_TOKEN = 'find' + upperTableName + 'Consumer';
//    var extension;
    var strategy;

//    oauth.serializeClient(function (client, done) {
//        return done(null, client.id);
//    });
//
//    oauth.deserializeClient(function (id, done) {
//        console.log('Deserialize', id);
//        done(null, id);
//    });

    /**
     * Create a request token table this table will expire so that we do not allow for
     * long requests.
     */
    schema.plugin(Token.plugin, {
        tableName: REQUEST_TOKEN,
        expire: options.requestTokenExpire,
        expires: options.requestTokenExpires
    });
    schema.plugin(Token.plugin, {
        tableName: upperTableName + 'Consumer'
    });

    //-------------------------------------------------------------------------
    //
    // Private Methods
    //
    //-------------------------------------------------------------------------

    function useStrategy(Model) {
        if (!strategy) {
            passport.use('consumer', new ConsumerStrategy(
                function (consumerKey, done) {
                    createRequestToken(Model, consumerKey, done);
                },
                function (requestToken, done) {
                    console.log('!!!!--------------------!!!!Request Token', requestToken);
                    Model[TYPE](function (err, Token) {
                        Token.findOne(requestToken, function (err, token) {
                            if (err) {
                                return done(err);
                            }
                            if (!token) {
                                return done(null, false);
                            }
                            // third argument is optional info.  typically used to pass
                            // details needed to authorize the request (ex: `verifier`)
                            return done(null, token.secret, { verifier: token.verifier });
                        });
                    });
                },
                function (timestamp, nonce, done) {
                    // validate the timestamp and nonce as necessary
                    done(null, true);
                }
            ));
        }
    }

    /**
     * Create and return the request token.
     * If invalid params are supplied of the consumer can not
     * be found this will send oauth error codes in the header
     * @param Model
     * @param consumerKey
     * @param done
     */
    function createRequestToken(Model, consumerKey, done) {
        Model[FIND_CONSUMER_BY_KEY](consumerKey, function (err, consumer) {
            if (err) {
                log.error('Error finding consumer', err);
                return done(null, false);
            }
            if (!consumer) {
                return done(null, false);
            }
            consumer[FIND_CONSUMER_TOKEN](function (err, token) {
                if (err) {
                    log.error('Error finding consumer secret', err);
                }
                done(err, consumer, token.secret);
            });
        });
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
