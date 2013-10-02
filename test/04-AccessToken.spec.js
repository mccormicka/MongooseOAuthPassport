'use strict';

/*jshint camelcase:false */
describe('04 - AccessToken Tests', function () {

    var CONSUMER_KEY = '$2a$04$x2jefs5s63LvWzU9i.pReOhXuTqrIopguZgad6g9BUZbOrDuVdVom';
    var CONSUMER_SECRET = '$2a$04$x2jefs5s63LvWzU9i.pReOKDGTFptcIFt2OLp5HS68VnlWYVJSmMW';
    var REQUEST_TOKEN = '$2a$04$UEhqkdECFTnaZj1N58feIelltVXoBOy6gGTfTk6d4SK41WHBYiBGW';
    var REQUEST_SECRET = '$2a$04$UEhqkdECFTnaZj1N58feIe64HGpL6REz0X2/VQOM1ZD57XQxcsZwa';
    var VERIFIER = '$2a$10$HgYEkMk3UuJexTBHYtV77e8kZWsNlSHgN9S7pHS/rGzkrR2OtucrO';

    var url = require('url');
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
            url: '/oauth/access_token',
            method: 'POST',
            setHeader: function () {
                console.log('Set Header', arguments);
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
            connection: 'keep-alive',
            'content-length': '0',
            authorization: 'OAuth ' +
                'oauth_consumer_key="%242a%2404%24x2jefs5s63LvWzU9i.pReOhXuTqrIopguZgad6g9BUZbOrDuVdVom",' +
                'oauth_nonce="64af6c4beca82304eb04fd7d8536ebf9",' +
                'oauth_signature_method="HMAC-SHA1",' +
                'oauth_timestamp="1380667073",' +
                'oauth_version="1.0",' +
                'oauth_token="%242a%2404%24UEhqkdECFTnaZj1N58feIelltVXoBOy6gGTfTk6d4SK41WHBYiBGW",' +
                'oauth_verifier="%242a%2410%24HgYEkMk3UuJexTBHYtV77e8kZWsNlSHgN9S7pHS%2FrGzkrR2OtucrO",' +
                'oauth_signature="7VKGk4bsZxTIXlmwJG0h1bJ6Od0%3D"',
            cookie: 'connect.sid=s%3Aob1O%2BnP3HSW1VaaQSItcGm1K.5En47uEYt01ZdQ0tY%2BXIaf6HyXrHVTRTHkwNBdvuGIc'
        };
    };

    var model;
    var consumer;
    var requestToken;

    beforeEach(function (done) {
        mockgoose.reset();
        Model.create({}, function (err, models) {
            model = models;
            model.createRandomTableNameConsumer(function (err, consumers) {
                consumer = consumers;
                consumer.key = CONSUMER_KEY;
                consumer.secret = CONSUMER_SECRET;
                consumer.save(function () {
                    model.createRandomTableNameRequestToken(function (err, requestTokens) {
                        requestToken = requestTokens;
                        requestToken.key = REQUEST_TOKEN;
                        requestToken.secret = REQUEST_SECRET;
                        requestToken.verifier = VERIFIER;
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

    afterEach(function(done){
        mockgoose.reset();
        done();
    });

    describe('SHOULD', function () {

        it('Add a accessToken method to our model', function (done) {
            expect(typeof Model.accessToken === 'function').toBe(true);
            done();
        });

        describe('Authorized', function () {
            it('Respond with an access token and secret', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                spyOn(res, 'end').andCallFake(function (value) {
                    expect(value).toContain('oauth_token=');
                    expect(value).toContain('&oauth_token_secret=');
                    done();
                });
                spyOn(Model, 'isValidTimeStamp').andCallFake(function () {
                    return true;
                });
                initialize(req, res, next);
                session(req, res, next);
                Model.accessToken(req, res, function () {
                });
            });

            it('Add an access token to Mongoose', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                spyOn(res, 'end').andCallFake(function () {
                    model.RandomTableNameAccessToken().find({}, function(err, results){
                        expect(err).toBeNull();
                        expect(results).toBeDefined();
                        if(results){
                            expect(results.length).toBe(1);
                            expect(results[0].modelId).toBe(model._id.toString());
                            done(err);
                        }else{
                            done('Error retrieving Access tokens');
                        }
                    });
                });
                spyOn(Model, 'isValidTimeStamp').andCallFake(function () {
                    return true;
                });
                initialize(req, res, next);
                session(req, res, next);
                Model.accessToken(req, res, function () {
                });
            });

        });

        describe('UNAuthorized', function () {

            it('Respond unauthorized if no params sent', function (done) {
                var req = new Request();
                var res = new Response();
                spyOn(res, 'end').andCallFake(function (value) {
                    expect(value).toBe('Unauthorized');
                    done();
                });
                initialize(req, res, next);
                session(req, res, next);
                Model.accessToken(req, res, function () {
                });
            });

            it('Return an error if the verifier is invalid', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                req.headers.authorization = req.headers.authorization.replace(
                    '%242a%2410%24HgYEkMk3UuJexTBHYtV77e8kZWsNlSHgN9S7pHS%2FrGzkrR2OtucrO',
                    'invalidVerifier');
                spyOn(res, 'end').andCallFake(function (value) {
                    expect(value).toBe('Unauthorized');
                    done();
                });
                spyOn(Model, 'isValidTimeStamp').andCallFake(function () {
                    return true;
                });
                initialize(req, res, next);
                session(req, res, next);
                Model.accessToken(req, res, function () {
                });
            });

            it('Return an error if the request token is invalid', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                req.headers.authorization = req.headers.authorization.replace(
                    '%242a%2404%24UEhqkdECFTnaZj1N58feIelltVXoBOy6gGTfTk6d4SK41WHBYiBGW',
                    'invalidToken');
                spyOn(res, 'end').andCallFake(function (value) {
                    expect(value).toBe('Unauthorized');
                    done();
                });
                spyOn(Model, 'isValidTimeStamp').andCallFake(function () {
                    return true;
                });
                initialize(req, res, next);
                session(req, res, next);
                Model.accessToken(req, res, function () {
                });
            });

            it('Return an error if the request consumer is not the same as the requesttoken consumer', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                requestToken.update({modelId: 'fakeconsumer!!'}, function () {

                    spyOn(res, 'end').andCallFake(function (value) {
                        expect(value).toBe('oauth_problem=token_rejected&oauth_problem_advice=access%20token%20not%20issued');
                        done();
                    });
                    spyOn(Model, 'isValidTimeStamp').andCallFake(function () {
                        return true;
                    });
                    initialize(req, res, next);
                    session(req, res, next);
                    Model.accessToken(req, res, function () {
                    });
                });
            });
        });
    });
});