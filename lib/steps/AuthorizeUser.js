'use strict';

exports = module.exports = function Plugin(schema, options) {
    var log = require('nodelogger').Logger('MongooseOAuthPassport:' + __filename);

    if (!options.tableName) {
        throw log.error('You must specify a tableName in the options when creating a MongooseAuthOAuth');
    }

    if (!options.oauthorize) {
        throw log.error('You must provide an instance of OAuthorize.js in order for MongooseOAuthPassport to work correctly with OAuth');
    }

    /**
     * Authorize a user.
     * @param req
     * @param res
     * @param parse
     * @param next
     */
    schema.statics.authorizeUser = function (req, res, parse, next) {
        this.useConsumerStrategy();
        authorizeUser(this, req, res, parse, next);
    };

    //-------------------------------------------------------------------------
    //
    // Private Methods
    //
    //-------------------------------------------------------------------------

    var oauth = options.oauthorize;
    var upperTableName = options.tableName.slice(0, 1).toUpperCase() + options.tableName.slice(1);
    var FIND_REQUEST_TOKEN = 'find' + upperTableName + 'RequestTokenByKey';

    function authorizeUser(Model, req, res, parse, next) {
        if (typeof next !== 'function' && typeof parse === 'function') {
            next = parse;
            parse = null;
        }
        var auth = oauth.userAuthorization(parse, function (requestToken, params, done) {
            Model[FIND_REQUEST_TOKEN](requestToken, function (err, token) {
                if (err) {
                    return done(err);
                }
                if (!token) {
                    return done(null, false);
                }
                Model.findOne({_id: token.modelId}, function (err, consumer) {
                    if (err) {
                        return done(err);
                    }
                    if (!consumer) {
                        return done(null, false);
                    }
                    done(null, consumer, token.callbackURL, params);
                });
            });
        });
        auth(req, res, function (err, result) {
            log.info(req.oauth);
            next(err, result);
        });
    }
};