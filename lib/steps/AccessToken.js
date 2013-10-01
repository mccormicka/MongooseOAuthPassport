'use strict';

exports = module.exports = function Plugin(schema, options) {
    var log = require('nodelogger').Logger('MongooseOAuthPassport:' + __filename);

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
                    console.log('Consumer-------------------- ', consumer, requestToken, info);
                    done(null, '1234', '12345');
                })(req, res, function (err) {
                oauth.errorHandler()(err, req, res, next);
            });
        });
    }
};