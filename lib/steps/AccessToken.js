'use strict';

exports = module.exports = function Plugin(schema, options) {
    var log = require('nodelogger').Logger('MongooseOAuthPassport:' + __filename);
    var Token = require('MongooseToken');

    if (!options.tableName) {
        throw log.error('You must specify a tableName in the options when creating a MongooseAuthOAuth');
    }

    if (!options.passport) {
        throw log.error('You must provide an instance of Passport.js in order for MongooseAuthOauth to work correctly with OAuth');
    }

    if (!options.oauthorize) {
        throw log.error('You must provide an instance of OAuthorize.js in order for MongooseOAuthPassport to work correctly with OAuth');
    }

    schema.statics.accessToken = function (req, res, next) {
        this.useConsumerStrategy();
        accessToken(req, res, next);
    };

    //-------------------------------------------------------------------------
    //
    // Private Methods
    //
    //-------------------------------------------------------------------------

    var passport = options.passport;
    var oauth = options.oauthorize;

    var upperTableName = options.tableName.slice(0, 1).toUpperCase() + options.tableName.slice(1);
    var lowerTableName = options.tableName.slice(0, 1).toLowerCase() + options.tableName.slice(1);
    var ACCESS_TOKEN = lowerTableName + 'AccessToken';
    var CREATE_ACCESS_TOKEN = 'create' + upperTableName + 'AccessToken';

    /**
     * Create a request token table this table will expire so that we do not allow for
     * long requests.
     */
    schema.plugin(Token.plugin, {
        tableName: ACCESS_TOKEN,
        unique:false,
        schema:{
            consumerId:String,
            userId:String
        }
    });

    function accessToken(req, res, next) {
        passport.authenticate('consumer', {session: false})(req, res, function () {
            oauth.accessToken(
                function (requestToken, verifier, info, done) {
                    if (verifier !== info.verifier || requestToken !== info.oauth.token) {
                        log.warn('Invalid verifier token combination', verifier, ' info ', info);
                        return done(null, false);
                    }
                    return done(null, true);
                },
                function (consumer, requestToken, info, done) {
                    //info = RequestToken
                    if(consumer._id.toString() !== info.modelId){
                        log.warn('invalid Access Token request', consumer, info);
                        return done(null, false);
                    }
                    consumer[CREATE_ACCESS_TOKEN]({userId:info.userId}, function(err, token){
                        if(err){
                            log.error(err);
                            return done(err);
                        }
                        return done(null, token.key, token.secret);
                    });
                })(req, res, function (err) {
                oauth.errorHandler()(err, req, res, next);
            });
        });
    }
};