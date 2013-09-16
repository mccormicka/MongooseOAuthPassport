'use strict';

exports = module.exports = function Consumer(schema, options){

    var log = require('nodelogger')('MongooseOAuthPassport:Consumer');
    if (!options || !options.passport) {
        throw log.error('You must provide an instance of Passport.js in order for MongooseAuthOauth to work correctly with OAuth');
    }
    if (!options.tableName) {
        throw log.error('You must specify a tableName in the options when creating a MongooseAuthOAuth');
    }
    if (!options.oauthorize) {
        throw log.error('You must provide an instance of OAuthorize.js in order for MongooseOAuthPassport to work correctly with OAuth');
    }

    var strategy;
    var Token = require('MongooseToken');
    var ConsumerStrategy = require('passport-http-oauth').ConsumerStrategy;
    var passport = options.passport;
    var oauth = options.oauthorize;
    var upperTableName = options.tableName.slice(0, 1).toUpperCase() + options.tableName.slice(1);
    var FIND_REQUEST_TOKEN = 'find' + upperTableName + 'RequestTokenByKey';
    var FIND_CONSUMER_BY_KEY = 'findBy' + upperTableName + 'ConsumerKey';
    var FIND_CONSUMER_TOKEN = 'find' + upperTableName + 'Consumer';

    schema.plugin(Token.plugin, {
        tableName: upperTableName + 'Consumer'
    });

    schema.statics.useConsumerStrategy = function(){
        if (!strategy) {
            var Model = this;
            passport.use('consumer', new ConsumerStrategy(
                validateRequestToken(Model),
                validateAccessToken(Model),
                function (timestamp, nonce, done) {
                    console.log('TODO::Validating NONCE HERE');
                    // validate the timestamp and nonce as necessary
                    done(null, true);
                }
            ));
            strategy = true;
        }
    };

    //-------------------------------------------------------------------------
    //
    // Private Methods
    //
    //-------------------------------------------------------------------------

    /**
     * Serialize the Consumer ID into the Session
     */
    oauth.serializeClient(function (consumer, done) {
        log.info('Consumer is ', consumer);
        return done(null, consumer.id);
    });

    /**
     * Deserialize the Consumer from the Session
     */
    oauth.deserializeClient(function (id, done) {
        log.info('Deserialize Consumer', id);
        done(null, id);
    });

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
};