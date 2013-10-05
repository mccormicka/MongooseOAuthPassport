'use strict';

exports = module.exports = function Consumer(schema, options){

    //-------------------------------------------------------------------------
    //
    // Public API
    //
    //-------------------------------------------------------------------------

    /**
     * Enable OAuth1 Authentication.
     * @param User
     * @param req
     * @param res
     * @param next
     */
    schema.statics.oauth1 = function(User, req, res, next){
        this.useTokenStrategy(User);
        passport.authenticate('token', { session: false })(req, res, next);
    };

    //-------------------------------------------------------------------------
    //
    // Private Methods
    //
    //-------------------------------------------------------------------------

    var log = require('nodelogger').Logger('MongooseOAuthPassport:' + __filename);
    if (!options || !options.passport) {
        throw log.error('You must provide an instance of Passport.js in order for MongooseAuthOauth to work correctly with OAuth');
    }
    if (!options.oauthorize) {
        throw log.error('You must provide an instance of OAuthorize.js in order for MongooseOAuthPassport to work correctly with OAuth');
    }
    var Utils = require('./Utils');
    var Nonce = require('./Nonce');
    var strategy;
    var TokenStrategy = require('passport-http-oauth').TokenStrategy;
    var passport = options.passport;
    var upperTableName = options.tableName.slice(0, 1).toUpperCase() + options.tableName.slice(1);
    var FIND_ACCESS_TOKEN = 'find' + upperTableName + 'AccessTokenByKey';

    /**
     * Tell Passport to use the Token Strategy.
     */
    schema.statics.useTokenStrategy = function(User){
        if (!strategy) {
            var Model = this;
            passport.use('token', new TokenStrategy(
                Utils.validateRequestToken(Model, options),
                validateAccessToken(Model, User),
                Nonce.validateNonce(Model, options)
            ));
            strategy = true;
        }
    };


    //-------------------------------------------------------------------------
    //
    // Private Methods
    //
    //-------------------------------------------------------------------------

    function validateAccessToken(Model, User){
        return function (accessToken, done){
            Model[FIND_ACCESS_TOKEN](accessToken, function(err, token){
                if(err || !token){
                    log.error('Error validating token', err);
                    return done(null, false);
                }
                User.findOne({_id:token.userId}, function(err, user){
                    if(err){
                        log.error('Error finding token user', err);
                        return done(err);
                    }
                    if(!user){
                        log.warn('Unable to find user for Access Token');
                        return done(null, false);
                    }
                    return done(null, user, token.secret, {});
                });
            });
        };
    }
};