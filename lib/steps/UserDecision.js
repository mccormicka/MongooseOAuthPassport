'use strict';

exports = module.exports = function Plugin(schema, options) {
    var log = require('nodelogger').Logger('MongooseOAuthPassport:' + __filename);
    var Utils = require('../Utils');

    if (!options.tableName) {
        throw log.error('You must specify a tableName in the options when creating a MongooseAuthOAuth');
    }

    if (!options.oauthorize) {
        throw log.error('You must provide an instance of OAuthorize.js in order for MongooseOAuthPassport to work correctly with OAuth');
    }

    /**
     * Handle a users decision
     * @param req
     * @param res
     * @param parse
     * @param next
     */
    schema.statics.userDecision = function(req, res, parse, next){
        this.useConsumerStrategy();
        userDecision(this, req, res, parse, next);
    };

    //-------------------------------------------------------------------------
    //
    // Private Methods
    //
    //-------------------------------------------------------------------------

    var oauth = options.oauthorize;
    var upperTableName = options.tableName.slice(0, 1).toUpperCase() + options.tableName.slice(1);
    var FIND_REQUEST_TOKEN = 'find' + upperTableName + 'RequestTokenByKey';

    function userDecision(Model, req, res, parse, next){
        if (typeof next !== 'function' && typeof parse === 'function'){
            next = parse;
            parse = function(req, next){next(null, {scope:Utils.getScope(req)});};
        }
        var decision = oauth.userDecision({redirectOnCancel:false}, parse, function(requestToken, user, res, done){
            log.debug('Found user Decision', requestToken, user, res);
            if(!user){
                return done('api.error.unauthorized', false);
            }
            Model[FIND_REQUEST_TOKEN](requestToken, function(err, token){
                if(err || !token){
                    log.error(err);
                    return done(err, false);
                }
                Model.hash(token.key + token.secret, 10, function(err, verifier){
                    log.debug('Created verifier', err, verifier);
                    token.verifier = verifier;
                    token.userId = user._id;
                    token.save(function(err){
                        if(err){
                            log.error(err);
                            return done(err);
                        }
                        done(null, verifier);
                    });
                });
            });
        });

        decision[0](req, res, function(){
            decision[1](req, res, function(err, result){
                log.debug('UserDecision', err, result);
                next(err, result);
            });
        });
    }
};