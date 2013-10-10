'use strict';

var logger = require('nodelogger').Logger(__filename);
exports = module.exports = function Nonce(schema, options){

    var _ = require('lodash');
    var Extension = require('mongooseextension');
    var moment = require('moment');
    var ms = require('ms');
    var upperTableName = options.tableName.slice(0, 1).toUpperCase() + options.tableName.slice(1);

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
};

/**
 * Validates the nonce against the database.
 * @type {Function}
 */
module.exports.validateNonce = validateNonce;
function validateNonce(Model, options) {
    var upperTableName = options.tableName.slice(0, 1).toUpperCase() + options.tableName.slice(1);
    var CREATE_CONSUMER_NONCE = 'create' + upperTableName + 'ConsumerNonce';
    var FIND_CONSUMER_NONCE = 'find' + upperTableName + 'ConsumerNonce';

    return function (timestamp, nonce, done) {
        if (!Model.isValidTimeStamp(timestamp, options.nonceExpires)) {
            logger.warn('Invalid Timestamp for nonce', nonce);
            return done(null, false);
        }
        Model[FIND_CONSUMER_NONCE]({nonce: nonce}, function (err, result) {
            if (result.length) {
                logger.warn('Nonce already registered!', nonce);
                return done(null, false);
            } else {
                Model[CREATE_CONSUMER_NONCE]({timestamp: timestamp, nonce: nonce}, function (err, result) {
                    logger.debug('Created Nonce', err, result);
                    return done(err, true);
                });
            }
        });
    };
}