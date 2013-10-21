'use strict';

exports = module.exports = function Consumer(schema, options) {

    //-------------------------------------------------------------------------
    //
    // Private Methods
    //
    //-------------------------------------------------------------------------

    var log = require('nodelogger').Logger('MongooseOAuthPassport:' + __filename);
    if (!options || !options.passport) {
        throw log.error('You must provide an instance of Passport.js in order for MongooseAuthOauth to work correctly with OAuth');
    }
    if (!options.tableName) {
        throw log.error('You must specify a tableName in the options when creating a MongooseAuthOAuth');
    }
    if (!options.oauthorize) {
        throw log.error('You must provide an instance of OAuthorize.js in order for MongooseOAuthPassport to work correctly with OAuth');
    }

    var Utils = require('./Utils');
    var Nonce = require('./Nonce');

    var strategy;
    var ConsumerStrategy = require('passport-http-oauth').ConsumerStrategy;
    var passport = options.passport;
    var oauth = options.oauthorize;
    var upperTableName = options.tableName.slice(0, 1).toUpperCase() + options.tableName.slice(1);
    var FIND_REQUEST_TOKEN = 'find' + upperTableName + 'RequestTokenByKey';

    /**
     * Tell Passport to use the Consumer Strategy.
     */
    schema.statics.useConsumerStrategy = function () {
        if (!strategy) {
            var Model = this;
            passport.use('consumer', new ConsumerStrategy(
                {ignoreVersion:true},
                Utils.validateRequestToken(Model, options),
                validateAccessToken(Model),
                Nonce.validateNonce(Model, options)
            ));
            strategy = true;
        }
    };

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

    /**
     * Validate the access token for the request.
     * @param Model
     * @returns {Function}
     */
    function validateAccessToken(Model) {
        return function (requestToken, done) {
            Model[FIND_REQUEST_TOKEN](requestToken, function (err, token) {
                if (err) {
                    log.error(err);
                    return done(err);
                }
                if (!token) {
                    return done(null, false);
                }
                done(null, token.secret, token);
            });
        };
    }
};