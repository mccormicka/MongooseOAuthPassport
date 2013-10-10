'use strict';

/**
 * OAuth/Passport.js/Mongoose Implementation middleware and plugin.
 * You can use this Plugin to annotate your own Mongoose Model with a
 * RequestToken method. This method will then handle creating your
 * Request Token/Secret pair and responding to the requester with the
 * appropriate OAuth values be them errors or valid Tokens.
 *
 * @options
 *      oauth if true you must pass an instance of passport.js in order
 *      for OAuthentication to work. If false then a cosumerkey and consumersecret
 *      will be created on your model so that you can use them outside of Passport.js
 *      passport should be your applications instance of Passport.js
 *
 * YourModelSchema.plugin(MongooseOauthPassport.plugin, {
 * oauth:true,
 * passport:require('passport')
 * }
 */
exports = module.exports = function Plugin(schema, options) {

    var _ = require('lodash');
    options = _.defaults(options || {}, {
        requestTokenExpire: true,
        requestTokenExpires: '10m',
        oauth: false
    });

    var log = require('nodelogger').Logger('MongooseOAuthPassport:' + __filename);

    if ((options.oauth && !options.passport)) {
        throw log.error('You must provide an instance of Passport.js in order for MongooseAuthOauth to work correctly with OAuth');
    }

    if (!options.tableName) {
        throw log.error('You must specify a tableName in the options when creating a MongooseAuthOAuth');
    }

    var oauth = require('oauthorize').createServer();
    options.oauthorize = oauth;

    //-------------------------------------------------------------------------
    //
    // Public Methods
    //
    //-------------------------------------------------------------------------

    var upperTableName = options.tableName.slice(0, 1).toUpperCase() + options.tableName.slice(1);
    var Token = require('mongoosetoken');

    schema.plugin(Token.plugin, {
        tableName: upperTableName + 'Consumer'
    });

    if (options.oauth) {
        //Only include OAuth if required.
        //Setup Nonce
        schema.plugin(require('./Nonce'), options);
        //Setup Passport Consumer Strategy
        schema.plugin(require('./ConsumerStrategy'), options);
        //Setup Passport Token Strategy
        schema.plugin(require('./TokenStrategy'), options);
        //Step 1 Retrieve a request token to authorize the application
        schema.plugin(require('./steps/RequestToken'), options);
        //Step 2 User Authorizes
        schema.plugin(require('./steps/AuthorizeUser'), options);
        //Step 3 Handle users Decision allow/deny
        schema.plugin(require('./steps/UserDecision'), options);
        //Step 4 give the requesting service an AccessToken to allow for interaction
        schema.plugin(require('./steps/AccessToken'), options);
    }
};
