'use strict';

exports = module.exports = function MongooseAuthOauth(schema, options) {
    if (!options || !options.passport) {
        throw new Error('You must provide an instance of Passport.js in order for MongooseAuthOauth to work correctly');
    }
    if (!options.consumerKeyMethodName || !options.consumerSecretMethodName) {
        throw new Error('You must provide a consumerKey method and consumerSecret method that can be called on this' +
            'object in the format function(next(err, result))');
    }
//
//    if (!options.tableName) {
//        throw new Error('You must specify a tableName in the options when creating a MongooseAuthOAuth');
//    }

    var passport = options.passport;
    var log = require('nodelogger')('MongooseAuthOAuth');
    var Token = require('MongooseToken');
//    var TYPE = options.tableName.toLowerCase();
//    var extension;
    var strategy;
    var oauth = require('oauthorize').createServer();

    var ConsumerStrategy = require('passport-http-oauth').ConsumerStrategy;
    var TokenStrategy = require('passport-http-oauth').TokenStrategy;
    schema.statics.requestToken = function (req, res, next) {
        useStrategy(this);
        passport.authenticate('consumer', {session: false})(req, res, function (err, result) {
            console.log('Error 1', err);
            console.log('Result 1', result);
            oauth.requestToken(function (client, callback, done) {

                console.log('Create tokens here', client, callback);
                done('random error', 'token', 'secret');

            })(req, res, function(err, result){
                log.debug('consumer:request_token', err, result);
                if(err){
                    next({message:'api.error.oauth', data:err});
                }else{
                    next(err, result);
                }
            });
        });
    };

    oauth.serializeClient(function (client, done) {
        return done(null, client.id);
    });

    oauth.deserializeClient(function (id, done) {
        console.log('Deserialize', id);
        done(null, id);
    });

    var TOKEN_NAME = schema.name + 'RequestToken';
    schema.plugin(Token.plugin, {tableName: TOKEN_NAME, expire: true, expires: '1m'});

    //-------------------------------------------------------------------------
    //
    // Private Methods
    //
    //-------------------------------------------------------------------------

    function useStrategy(Model) {
        if (!strategy) {
            passport.use('consumer', new ConsumerStrategy(
                function (consumerKey, done) {
                    Model[options.consumerKeyMethodName](consumerKey, function (err, consumer) {
                        console.log('Found Consumer', err, consumer);
                        if (err) {
                            log.error('Error finding consumer', err);
                            return done(err);
                        }
                        if (!consumer) {
                            return done(null, false);
                        }
                        consumer[options.consumerSecretMethodName](function (err, secret) {
                            if (err) {
                                log.error('Error finding consumer secret', err);
                            }
                            done(err, consumer, secret);
                        });
                    });
                },
                function (requestToken, done) {
                    console.log('Request Token', requestToken);
                    Model[TOKEN_NAME](function (err, Token) {
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
