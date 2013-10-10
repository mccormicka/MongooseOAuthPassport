'use strict';

/*jshint camelcase:false */
describe('03 - UserDecision Tests', function () {

    var CONSUMER_KEY = '$2a$04$9WIDR8lZY/tKwFI8sBcYTulhp.z9AvJ6lMgLNXRvh8vOM9APM.zrG';
    var CONSUMER_SECRET = '$2a$04$9WIDR8lZY/tKwFI8sBcYTuRMjA0SkURD2Bw9.DAZWnbiEWrHRZzEy';
    var REQUEST_TOKEN = '$2a$04$.sx9IW2Ab0Is6DF.9AocceqcfnMN7S9qDEP294hZHUk.xBEzzr6ua';
    var REQUEST_SECRET = '$2a$04$.sx9IW2Ab0Is6DF.9AocceC9rGc3RsoSpu8BG4L4PMP74XzvaesrS';

    var CALLBACKURL = 'http://localhost:3001/callback';
    var OAUTH_CALLBACK = 'http://localhost:3001/callback?oauth_token=%242a%2404%24.sx9IW2Ab0Is6DF.9AocceqcfnMN7S9qDEP294hZHUk.xBEzzr6ua&oauth_verifier=';

    var http = require('http');
    var reqProxy = http.IncomingMessage.prototype;
    var Passport = require('passport').Passport;
    var passport = new Passport();
    var mockgoose = require('mockgoose');
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
            },
            redirect: function () {
                console.log('Redirect is being called', arguments);
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

    function validRequest(req) {

        req.session = {
            authorize: {
                muPWLoOo: {
                    protocol: 'oauth',
                    client: 'fakeclient',
                    callbackURL: CALLBACKURL,
                    req: {
                        scope: 'email',
                        token: REQUEST_TOKEN
                    },
                    authz: {
                        scope: 'email',
                        token: REQUEST_TOKEN
                    }
                }
            }
        };
        req.body = {
            transaction_id: 'muPWLoOo',
            allow: 'submit'
        };

        req.user = {
            email: 'testing@testing.com'
        };
    }

    describe('SHOULD', function () {

        it('Add a userDecision method to our model', function (done) {
            expect(typeof Model.userDecision === 'function').toBe(true);
            done();
        });

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
                done();
            });

            initialize(req, res, next);
            session(req, res, next);
            validRequest(req);
            Model.userDecision(req, res, parse.parse, function (err) {
                done(err);
            });
        });

        it('Redirect back to caller if user accepts', function (done) {
            var req = new Request();
            var res = new Response();
            req.headers = new Headers();

            spyOn(res, 'redirect').andCallFake(function (value) {
                expect(value).toContain(OAUTH_CALLBACK);
                done();
            });

            initialize(req, res, next);
            session(req, res, next);
            validRequest(req);
            Model.userDecision(req, res, function (err) {
                expect(req.oauth.res.allow).toBe(true);
                done(err);
            });
        });

        it('Respond with an error if user is invalid', function (done) {
            var req = new Request();
            var res = new Response();
            req.headers = new Headers();

            spyOn(res, 'redirect').andCallFake(function (value) {
                console.log('REDIRECT TO', value);
                expect(value).toBe(OAUTH_CALLBACK);
                done();
            });

            initialize(req, res, next);
            session(req, res, next);
            validRequest(req);
            req.user = null;
            Model.userDecision(req, res, function (err) {
                expect(err).toBe('api.error.unauthorized');
                done();
            });
        });

        it('Respond with an error if user denies access', function (done) {
            var req = new Request();
            var res = new Response();
            req.headers = new Headers();

            initialize(req, res, next);
            session(req, res, next);
            validRequest(req);
            req.body.cancel = true;
            Model.userDecision(req, res, function (err) {
                expect(req.oauth.res.allow).toBe(false);
                done(err);
            });
        });


        it('Should create a Verifier token in mongoose', function (done) {
            var req = new Request();
            var res = new Response();
            req.headers = new Headers();
            spyOn(res, 'redirect').andCallFake(function () {
                Model.findRandomTableNameRequestTokenByKey(REQUEST_TOKEN, function (err, token) {
                    expect(err).toBeNull();
                    expect(token).toBeDefined();
                    if (token) {
                        expect(token.verifier).not.toBe('');
                        done();
                    } else {
                        done('Error finding ConsumerNonce');
                    }
                });
            });
            spyOn(Model, 'isValidTimeStamp').andCallFake(function(){
                return true;
            });

            initialize(req, res, next);
            session(req, res, next);
            validRequest(req);
            Model.userDecision(req, res, function () {
            });
        });
    });

});