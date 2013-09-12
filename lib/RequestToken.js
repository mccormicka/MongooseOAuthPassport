'use strict';

exports = module.exports = function MongooseAuthOauth(schema, options) {

    var log = require('nodelogger')('MongooseOAuthRequestToken');
    if (!options || !options.passport) {
        throw log.error('You must provide an instance of Passport.js in order for MongooseAuthOauth to work correctly');
    }
    if (!options.consumerKeyMethodName || !options.consumerSecretMethodName) {
        throw log.error('You must provide a consumerKey method and consumerSecret method that can be called on this' +
            'object in the format function(token, next(err, result))');
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
//    var extension;
    var strategy;

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

//    oauth.serializeClient(function (client, done) {
//        return done(null, client.id);
//    });
//
//    oauth.deserializeClient(function (id, done) {
//        console.log('Deserialize', id);
//        done(null, id);
//    });

    /**
     * Create a request token table.
     */
    schema.plugin(Token.plugin, {tableName: REQUEST_TOKEN, expire: true, expires: '1m'});

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
        Model[options.consumerKeyMethodName](consumerKey, function (err, consumer) {
            console.log('Found Consumer', err, consumer);
            if (err) {
                log.error('Error finding consumer', err);
                return done(err);
            }
            if (!consumer) {
                return done(null, false);
            }
            consumer[options.consumerSecretMethodName](consumerKey, function (err, secret) {
                if (err) {
                    log.error('Error finding consumer secret', err);
                }
                done(err, consumer, secret);
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
