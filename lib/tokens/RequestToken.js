'use strict';

exports = module.exports = function Plugin(schema, options) {
    var log = require('nodelogger')('MongooseOAuthPassport:RequestToken');
    var Token = require('MongooseToken');

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
            requestToken(this, req, res, parse, next);
        };
    }
    var passport = options.passport;
    var oauth = options.oauthorize;
    var REQUEST_TOKEN = options.lowerTableName + 'RequestToken';
    var CREATE_REQUEST_TOKEN = 'create' + options.upperTableName + 'RequestToken';

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
            userId:String
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
    function requestToken(self, req, res, parse, next) {
//        self.usePassportStrategy(self);
        if (typeof next !== 'function' && typeof parse === 'function'){
            next = parse;
            parse = null;
        }
        passport.authenticate('consumer', {session: false})(req, res, function () {
            var token = oauth.requestToken(parse, function (consumer, callbackURL, params, done) {
                consumer[CREATE_REQUEST_TOKEN]({callbackURL:callbackURL}, function (err, token) {
                    if (err) {
                        log.error('Error retrieving RequestToken Model', err);
                        done(err, false);
                    } else {
                        log.debug('Created RequestToken:token', token);
                        done(null, token.key, token.secret, params);
                    }
                });
            });

            token(req, res, function (err, result) {
                next(err, result);
            });
        });
    }
};