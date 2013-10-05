'use strict';

exports = module.exports = function Plugin(schema, options) {
    var log = require('nodelogger').Logger('MongooseOAuthPassport:' + __filename);
    var Token = require('MongooseToken');
    var Utils = require('../Utils');

    if (!options.tableName) {
        throw log.error('You must specify a tableName in the options when creating a MongooseAuthOAuth');
    }

    if (options.oauth) {

        if (!options.passport) {
            throw log.error('You must provide an instance of Passport.js in order for MongooseAuthOauth to work correctly with OAuth');
        }
        if(!options.oauthorize){
            throw log.error('You must provide an instance of OAuthorize.js in order for MongooseOAuthPassport to work correctly with OAuth');
        }
        /**
         * Request a Authorization token
         * @param req
         * @param res
         * @param parse
         * @param next
         */
        schema.statics.requestToken = function (req, res, parse, next) {
            this.useConsumerStrategy();
            requestToken(req, res, parse, next);
        };
    }

    var passport = options.passport;
    var oauth = options.oauthorize;
    var upperTableName = options.tableName.slice(0, 1).toUpperCase() + options.tableName.slice(1);
    var lowerTableName = options.tableName.slice(0, 1).toLowerCase() + options.tableName.slice(1);
    var REQUEST_TOKEN = lowerTableName + 'RequestToken';
    var CREATE_REQUEST_TOKEN = 'create' + upperTableName + 'RequestToken';

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
            callbackURL:String,
            verifier:String,
            userId:String,
            info:{}
        }
    });

    /**
     * Handle the Request Token
     * @param self
     * @param req
     * @param res
     * @param parse
     * @param next
     */

    function requestToken(req, res, parse, next) {
        if (typeof next !== 'function' && typeof parse === 'function'){
            next = parse;
            parse = function(res, done){
                done(null, {scope:Utils.getScope(res)});
            };
        }
        passport.authenticate('consumer', {session: false})(req, res, function () {
            var token = oauth.requestToken(parse, function (consumer, callbackURL, params, done) {
                consumer[CREATE_REQUEST_TOKEN]({callbackURL:callbackURL, info:params}, function (err, token) {
                    if (err) {
                        log.error('Error retrieving RequestToken Model', err);
                        done(err, false);
                    } else {
                        log.debug('Created RequestToken:token', token.key, token.secret);
                        done(null, token.key, token.secret, params);
                    }
                });
            });
            token(req, res, function (err) {
                log.warn('Should never get here!', err);
                oauth.errorHandler(err, req, res, next);
            });
        });
    }
};