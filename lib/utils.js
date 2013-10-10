'use strict';

var logger = require('nodelogger').Logger(__filename);

module.exports.getScope = getScope;

function getScope(req){
    return req && req.query ? req.query.scope : null;
}

module.exports.validateRequestToken = validateRequestToken;

/**
 * Validates a request token against the model.
 * @param Model
 * @param options
 * @returns {Function}
 */
function validateRequestToken(Model, options) {
    var upperTableName = options.tableName.slice(0, 1).toUpperCase() + options.tableName.slice(1);
    var FIND_CONSUMER_BY_KEY = 'findBy' + upperTableName + 'ConsumerKey';
    var FIND_CONSUMER_TOKEN = 'find' + upperTableName + 'Consumer';

    return function (consumerKey, done) {
        Model[FIND_CONSUMER_BY_KEY](consumerKey, function (err, consumer) {
            if (err) {
                logger.error('Error finding consumer', err);
                return done(null, false);
            }
            if (!consumer) {
                return done(null, false);
            }
            consumer[FIND_CONSUMER_TOKEN](function (err, tokens) {
                if (err) {
                    logger.error('Error finding consumer secret', err);
                }
                var token = tokens[0];
                if (!token) {
                    return done(null, false);
                }
                done(err, consumer, token.secret);
            });
        });
    };
}