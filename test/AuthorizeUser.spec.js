'use strict';

/*jshint camelcase:false */
describe('AuthorizeUser Tests', function () {

    var CONSUMER_KEY = '$2a$04$9WIDR8lZY/tKwFI8sBcYTulhp.z9AvJ6lMgLNXRvh8vOM9APM.zrG';
    var CONSUMER_SECRET = '$2a$04$9WIDR8lZY/tKwFI8sBcYTuRMjA0SkURD2Bw9.DAZWnbiEWrHRZzEy';
    var REQUEST_TOKEN = '$2a$04$.sx9IW2Ab0Is6DF.9AocceqcfnMN7S9qDEP294hZHUk.xBEzzr6ua';
    var REQUEST_SECRET = '$2a$04$.sx9IW2Ab0Is6DF.9AocceC9rGc3RsoSpu8BG4L4PMP74XzvaesrS';

    var http = require('http');
    var reqProxy = http.IncomingMessage.prototype;
    var Passport = require('passport').Passport;
    var passport = new Passport();
    var mockgoose = require('Mockgoose');
    var mongoose = require('mongoose');
    mockgoose(mongoose);
    var db = mongoose.createConnection('mongodb://localhost:3001/Whatever');
    var Index = require('../index');
    var schema = new mongoose.Schema();
    //Add our OAuth Plugin
    schema.plugin(Index.plugin,
        {
            tableName: 'randomTableName',
            schema: {name: String},
            oauth: true,
            passport: passport
        });

    var Model = db.model('randommodel', schema);

    var initialize = passport.initialize();
    var session = passport.session();
    var next = function () {
    };

    var Request = function () {
        return {
            logIn: reqProxy.logIn,
            logOut: reqProxy.logOut,
            isAuthenticated: reqProxy.isAuthenticated,
            isUnauthenticated: reqProxy.isUnauthenticated,
            connection: {
                encrypted: false
            },
            method: 'GET',
            query: {
                scope: 'email',
                oauth_token: REQUEST_TOKEN,
                oauth_callback: 'http://localhost:8888/oauth/sozialize_oauth.php'
            },

            setHeader: function () {
                console.log('Set Header', arguments);
            },
            session: function () {
                console.log('Session called', arguments);
            }
        };
    };
    var Response = function () {
        return {
            setHeader: function () {
                console.log('Set Header', arguments);
            },
            end: function () {
                console.log('End is being called.', arguments);
            }
        };
    };
    var Headers = function () {
        return {
            host: 'localhost:3001',
            cookie: 'connect.sid=s%3Aob1O%2BnP3HSW1VaaQSItcGm1K.5En47uEYt01ZdQ0tY%2BXIaf6HyXrHVTRTHkwNBdvuGIc'
        };
    };

    beforeEach(function (done) {
        mockgoose.reset();
        Model.create({}, function (err, model) {
            model.createRandomTableNameConsumer(function (err, consumer) {
                consumer.key = CONSUMER_KEY;
                consumer.secret = CONSUMER_SECRET;
                consumer.save(function () {
                    model.createRandomTableNameRequestToken(function (err, requestToken) {
                        requestToken.key = REQUEST_TOKEN;
                        requestToken.secret = REQUEST_SECRET;
                        requestToken.save(function () {
                            model.save(function () {
                                done();
                            });
                        });
                    });
                });
            });
        });
    });

    describe('SHOULD', function () {

        it('Call parse method if one supplied', function (done) {
            var req = new Request();
            var res = new Response();
            req.headers = new Headers();
            var parse = {
                parse: function () {
                }
            };
            spyOn(parse, 'parse').andCallFake(function (req, next) {
                next(null, {scope: 'email'});
            });
            spyOn(res, 'end').andCallFake(function (value) {
                expect(value).toContain('email');
                expect(parse.parse).toHaveBeenCalled();
                done();
            });
            initialize(req, res, next);
            session(req, res, next);
            Model.authorizeUser(req, res, parse.parse, function (err) {
                done(err);
            });
        });

        describe('Authorized', function () {
            it('Add oauthorization params to req if valid', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                var parse = {
                    parse: function () {
                    }
                };
                spyOn(parse, 'parse').andCallFake(function (req, next) {
                    next(null, {scope: 'email'});
                });
                spyOn(res, 'end').andCallFake(function (value) {
                    expect(value).toContain('email');
                    expect(parse.parse).toHaveBeenCalled();
                    done();
                });
                initialize(req, res, next);
                session(req, res, next);
                Model.authorizeUser(req, res, parse.parse, function (err) {
                    var oauth = req.oauth;
                    expect(oauth).toBeDefined();
                    if (oauth) {
                        expect(oauth.authz.scope).toBe('email');
                        expect(oauth.authz.token).toBe(REQUEST_TOKEN);
                        expect(oauth.transactionID).toBeDefined();
                    }
                    done(err);
                });
            });
        });

        describe('UnAuthorized', function () {
            it('Add oauthorization params to req if valid', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                req.query.oauth_token = 'invalid_token';
                initialize(req, res, next);
                session(req, res, next);
                Model.authorizeUser(req, res, function (err, result) {
                    console.log('ERROR RESULT', err, result);
                    expect(err).toBeDefined();
                    if (err) {
                        expect(err).toEqual({ name: 'AuthorizationError',
                            message: 'request token not valid',
                            code: 'token_rejected',
                            status: 401 });
                        done();
                    } else {
                        done('Invalid authorization token should throw an error');
                    }
                });
            });
        });
    });
});