'use strict';

exports = module.exports = function Consumer(schema, options){

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

    var strategy;
    var moment = require('moment');
    var ms = require('ms');
    var _ = require('lodash');
    var Extension = require('MongooseExtension');
    var ConsumerStrategy = require('passport-http-oauth').ConsumerStrategy;
    var passport = options.passport;
    var oauth = options.oauthorize;
    var upperTableName = options.tableName.slice(0, 1).toUpperCase() + options.tableName.slice(1);
    var FIND_REQUEST_TOKEN = 'find' + upperTableName + 'RequestTokenByKey';
    var FIND_CONSUMER_BY_KEY = 'findBy' + upperTableName + 'ConsumerKey';
    var FIND_CONSUMER_TOKEN = 'find' + upperTableName + 'Consumer';
    var CREATE_CONSUMER_NONCE = 'create' + upperTableName + 'ConsumerNonce';
    var FIND_CONSUMER_NONCE = 'find' + upperTableName + 'ConsumerNonce';

    options = _.defaults(options, {nonceExpires:'1m'});

    schema.plugin(Extension.plugin, {
        tableName:upperTableName+'ConsumerNonce',
        schema:{
            timestamp:String,
            nonce:String,
            expire:{
                type: Date,
                expires: options.nonceExpires,
                'default': Date.now
            }
        }
    });

    /**
     * Validate timestamp against nonce expiry date
     * @param timestamp
     * @param duration
     * @returns {*}
     */
    schema.statics.isValidTimeStamp = function(timestamp, duration){
        var timeAgo = moment(moment().unix()-(ms(duration)/1000), 'X');
        return moment(timestamp, 'X').isAfter(timeAgo);
    };

    /**
     * Tell Passport to use the Consumer Strategy.
     */
    schema.statics.useConsumerStrategy = function(){
        if (!strategy) {
            var Model = this;
            passport.use('consumer', new ConsumerStrategy(
                validateRequestToken(Model),
                validateAccessToken(Model),
                function (timestamp, nonce, done) {
                    if(!Model.isValidTimeStamp(timestamp, options.nonceExpires)){
                        log.error('Invalid Timestamp for nonce', nonce);
                        return done(null, false);
                    }
                    Model[FIND_CONSUMER_NONCE]({nonce:nonce}, function(err, result){
                        if(result.length){
                            log.error('Nonce already registered!', nonce);
                            return done(null, false);
                        }
                        else{
                            Model[CREATE_CONSUMER_NONCE]({timestamp:timestamp, nonce:nonce}, function(err, result){
                                log.debug('Created Consumer Nonce', err, result);
                                done(err, true);
                            });
                        }

                    });
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