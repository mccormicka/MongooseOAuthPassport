'use strict';

/*jshint camelcase:false */
describe('01 - RequestToken Tests', function () {

    var url = require('url');
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
            passport: passport,
            version:'1.0'
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
            url: '/oauth/request_token',
            method: 'POST',
            setHeader: function () {
//                console.log('Set Header', arguments);
            }
        };
    };
    var Response = function () {
        return {
            setHeader: function () {
//                console.log('Set Header', arguments);
            },
            end: function () {
//                console.log('End is being called.', arguments);
            }
        };
    };
    var Headers = function () {
        return {
            host: 'localhost:3001',
            connection: 'keep-alive',
            'content-length': '0',
            authorization: 'OAuth ' +
                'realm="http://localhost:3001/oauth/request_token",' +
                'oauth_consumer_key="$2a$04$9WIDR8lZY/tKwFI8sBcYTulhp.z9AvJ6lMgLNXRvh8vOM9APM.zrG",' +
                'oauth_signature_method="HMAC-SHA1",' +
                'oauth_timestamp="1378941993",' +
                'oauth_nonce="XHfvSy",' +
                'oauth_version="1.0",' +
                'oauth_signature="6nbK%2F2FOS2B2wl4wNEHcICT32zY%3D"',
            origin: 'chrome-extension://pchdfiagnfhagoefbaeigofbdnjheddc',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.65 Safari/537.36',
            accept: '*/*',
            'accept-encoding': 'gzip,deflate,sdch',
            'accept-language': 'en-US,en;q=0.8',
            cookie: 'connect.sid=s%3Aob1O%2BnP3HSW1VaaQSItcGm1K.5En47uEYt01ZdQ0tY%2BXIaf6HyXrHVTRTHkwNBdvuGIc'
        };
    };

    beforeEach(function (done) {
        mockgoose.reset();
        Model.create({}, function (err, result) {
            result.createRandomTableNameConsumer(function (err, result) {
                result.key = '$2a$04$9WIDR8lZY/tKwFI8sBcYTulhp.z9AvJ6lMgLNXRvh8vOM9APM.zrG';
                result.secret = '$2a$04$9WIDR8lZY/tKwFI8sBcYTuRMjA0SkURD2Bw9.DAZWnbiEWrHRZzEy';
                result.save(done);
            });
        });
    });

    describe('SHOULD', function () {

        it('Add a requestToken method to our model', function (done) {
            expect(typeof Model.requestToken === 'function').toBe(true);
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
                next(null, {analytics: 'someanalytics'});
            });
            spyOn(res, 'end').andCallFake(function (value) {
                expect(value).toContain('someanalytics');
                expect(parse.parse).toHaveBeenCalled();
                done();
            });
            spyOn(Model, 'isValidTimeStamp').andCallFake(function(){
                return true;
            });
            initialize(req, res, next);
            session(req, res, next);
            Model.requestToken(req, res, parse.parse, function () {
            });
        });

        describe('Unauthorized', function () {

            it('Respond unauthorized if no params sent', function (done) {
                var req = new Request();
                var res = new Response();
                spyOn(res, 'end').andCallFake(function (value) {
                    expect(value).toBe('Unauthorized');
                    done();
                });
                spyOn(Model, 'isValidTimeStamp').andCallFake(function(){
                    return true;
                });
                Model.requestToken(req, res, function () {
                });
            });

            it('Respond unauthorized if no consumer key params sent', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                req.headers.authorization = 'OAuth ' +
                    'realm="http://localhost:3001/oauth/request_token",' +
                    'oauth_signature_method="HMAC-SHA1",' +
                    'oauth_timestamp="1378941993",' +
                    'oauth_nonce="XHfvSy",' +
                    'oauth_version="1.0",' +
                    'oauth_signature="6nbK%2F2FOS2B2wl4wNEHcICT32zY%3D"';
                spyOn(res, 'setHeader').andCallFake(function () {
                    expect(arguments[1]).toEqual([ 'OAuth realm="Clients", oauth_problem="parameter_absent"' ]);
                });
                spyOn(res, 'end').andCallFake(function (value) {
                    expect(value).toEqual('Unauthorized');
                    done();
                });
                spyOn(Model, 'isValidTimeStamp').andCallFake(function(){
                    return true;
                });
                initialize(req, res, next);
                session(req, res, next);
                Model.requestToken(req, res, function () {
                });
            });

            it('Respond unauthorized if invalid consumer key params sent', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                req.headers.authorization = 'OAuth ' +
                    'oauth_consumer_key="$2a$04$9WIDR8lZY/tKwFI8sBcYTulhp.z9AvJ6lMgLNXRvh8vOM9APM.wrong",' +
                    'realm="http://localhost:3001/oauth/request_token",' +
                    'oauth_signature_method="HMAC-SHA1",' +
                    'oauth_timestamp="1378941993",' +
                    'oauth_nonce="XHfvSy",' +
                    'oauth_version="1.0",' +
                    'oauth_signature="6nbK%2F2FOS2B2wl4wNEHcICT32zY%3D"';
                spyOn(res, 'setHeader').andCallFake(function () {
                    expect(arguments[1]).toEqual([ 'OAuth realm="Clients", oauth_problem="consumer_key_rejected"' ]);
                });
                spyOn(res, 'end').andCallFake(function (value) {
                    expect(value).toEqual('Unauthorized');
                    done();
                });
                spyOn(Model, 'isValidTimeStamp').andCallFake(function(){
                    return true;
                });
                initialize(req, res, next);
                session(req, res, next);
                Model.requestToken(req, res, function () {
                });
            });

            it('Respond unauthorized if invalid signature params sent', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                req.headers.authorization = 'OAuth ' +
                    'oauth_consumer_key="$2a$04$9WIDR8lZY/tKwFI8sBcYTulhp.z9AvJ6lMgLNXRvh8vOM9APM.zrG",' +
                    'realm="http://localhost:3001/oauth/request_token",' +
                    'oauth_signature_method="HMAC-SHA1",' +
                    'oauth_timestamp="1378941993",' +
                    'oauth_nonce="XHfvSy",' +
                    'oauth_version="1.0",' +
                    'oauth_signature="invalid6nbK%2F2FOS2B2wl4wNEHcICT32zY%3D"';
                spyOn(res, 'setHeader').andCallFake(function () {
                    expect(arguments[1]).toEqual([ 'OAuth realm="Clients", oauth_problem="signature_invalid"' ]);
                });
                spyOn(res, 'end').andCallFake(function (value) {
                    expect(value).toEqual('Unauthorized');
                    done();
                });
                spyOn(Model, 'isValidTimeStamp').andCallFake(function(){
                    return true;
                });
                initialize(req, res, next);
                session(req, res, next);
                Model.requestToken(req, res, function () {
                });
            });

            it('Respond unauthorized if invalid timestamp param sent', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                req.headers.authorization = 'OAuth ' +
                    'realm="http://localhost:3001/oauth/request_token",' +
                    'oauth_consumer_key="$2a$04$9WIDR8lZY/tKwFI8sBcYTulhp.z9AvJ6lMgLNXRvh8vOM9APM.zrG",' +
                    'oauth_signature_method="HMAC-SHA1",' +
                    'oauth_timestamp="1378941993",' +
                    'oauth_nonce="XHfvSy",' +
                    'oauth_version="1.0",' +
                    'oauth_signature="6nbK%2F2FOS2B2wl4wNEHcICT32zY%3D"';
                spyOn(res, 'setHeader').andCallFake(function () {
                    expect(arguments[1]).toEqual([ 'OAuth realm="Clients", oauth_problem="nonce_used"' ]);
                });
                spyOn(res, 'end').andCallFake(function (value) {
                    expect(value).toEqual('Unauthorized');
                    done();
                });

                initialize(req, res, next);
                session(req, res, next);
                Model.requestToken(req, res, function () {
                });
            });

            it('Respond unauthorized if invalid nonce param sent', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                req.headers.authorization = 'OAuth ' +
                    'realm="http://localhost:3001/oauth/request_token",' +
                    'oauth_consumer_key="$2a$04$9WIDR8lZY/tKwFI8sBcYTulhp.z9AvJ6lMgLNXRvh8vOM9APM.zrG",' +
                    'oauth_signature_method="HMAC-SHA1",' +
                    'oauth_timestamp="1378941993",' +
                    'oauth_nonce="XHfvS",' +
                    'oauth_version="1.0",' +
                    'oauth_signature="6nbK%2F2FOS2B2wl4wNEHcICT32zY%3D"';
                spyOn(res, 'setHeader').andCallFake(function () {
                    expect(arguments[1]).toEqual([ 'OAuth realm="Clients", oauth_problem="signature_invalid"' ]);
                });
                spyOn(res, 'end').andCallFake(function (value) {
                    expect(value).toEqual('Unauthorized');
                    done();
                });

                initialize(req, res, next);
                session(req, res, next);
                Model.requestToken(req, res, function () {
                });
            });
        });

        describe('Authorized', function () {

            it('Return a request token and secret when passed a valid set of params pair', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                spyOn(res, 'end').andCallFake(function (value) {
                    expect(value).toContain('oauth_callback_confirmed=true');
                    expect(value).toContain('oauth_token');
                    expect(value).toContain('oauth_token_secret');
                    done();
                });
                spyOn(Model, 'isValidTimeStamp').andCallFake(function(){
                    return true;
                });
                initialize(req, res, next);
                session(req, res, next);
                Model.requestToken(req, res, function () {
                });
            });

            it('Should create a request token in mongoose', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                spyOn(res, 'end').andCallFake(function (value) {
                    var oauth = url.parse('http:localhost/?' + value, true).query;
                    expect(oauth.oauth_token).toBeTruthy();
                    expect(oauth.oauth_token_secret).toBeTruthy();
                    expect(oauth.oauth_callback_confirmed).toBeTruthy();
                    Model.findRandomTableNameRequestTokenByKey(oauth.oauth_token, function (err, token) {
                        expect(err).toBeNull();
                        expect(token).toBeDefined();
                        if (token) {
                            expect(token.secret).toBe(oauth.oauth_token_secret);
                            done();
                        } else {
                            done('Error finding token');
                        }
                    });
                });
                spyOn(Model, 'isValidTimeStamp').andCallFake(function(){
                    return true;
                });
                initialize(req, res, next);
                session(req, res, next);
                Model.requestToken(req, res, function () {
                });
            });

            it('Should create multiple request tokens in mongoose', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                var res2 = new Response();

                spyOn(res, 'end').andCallFake(function () {
                    spyOn(res2, 'end').andCallFake(function () {
                        Model.randomTableNameRequestToken(function (err, result) {
                            result.find({}, function (err, tokens) {
                                expect(err).toBeNull();
                                expect(tokens.length).toBe(2);
                                done(err);
                            });
                        });
                    });
                    spyOn(Model, 'findRandomTableNameConsumerNonce').andCallFake(function(options, next){
                        return next(null, []);
                    });
                    initialize(req, res2, next);
                    session(req, res2, next);
                    Model.requestToken(req, res2, function () {
                    });
                });
                spyOn(Model, 'isValidTimeStamp').andCallFake(function(){
                    return true;
                });
                initialize(req, res, next);
                session(req, res, next);
                Model.requestToken(req, res, function () {
                });
            });

            it('Should create a ConsumerNonce token in mongoose', function (done) {
                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                spyOn(res, 'end').andCallFake(function (value) {
                    var oauth = url.parse('http:localhost/?' + value, true).query;
                    expect(oauth.oauth_token).toBeTruthy();
                    expect(oauth.oauth_token_secret).toBeTruthy();
                    expect(oauth.oauth_callback_confirmed).toBeTruthy();

                    Model.findRandomTableNameConsumerNonce({nonce:'XHfvSy'}, function (err, token) {
                        expect(err).toBeNull();
                        expect(token.length).toBe(1);
                        if (token.length) {
                            expect(token[0].timestamp).toBe('1378941993');
                            expect(token[0].nonce).toBe('XHfvSy');
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
                Model.requestToken(req, res, function () {
                });
            });
        });

        describe('1.0a', function () {

            var ModelA;
            beforeEach(function(done){
                var schemaA = new mongoose.Schema();
                //Add our OAuth Plugin
                schemaA.plugin(Index.plugin,
                    {
                        tableName: 'randomTableNameA',
                        schema: {name: String},
                        oauth: true,
                        passport: passport,
                        version:'1.0a'
                    });
                ModelA = db.model('randommodelA', schemaA);
                ModelA.create({}, function (err, result) {
                    result.createRandomTableNameAConsumer(function (err, result) {
                        result.key = '$2a$04$9WIDR8lZY/tKwFI8sBcYTulhp.z9AvJ6lMgLNXRvh8vOM9APM.zrG';
                        result.secret = '$2a$04$9WIDR8lZY/tKwFI8sBcYTuRMjA0SkURD2Bw9.DAZWnbiEWrHRZzEy';
                        result.save(done);
                    });
                });
            });

            it('Respond unauthorized if 1.0a and no callback sent', function (done) {

                var req = new Request();
                var res = new Response();
                req.headers = new Headers();
                spyOn(res, 'end').andCallFake(function (value) {
                    expect(value).toContain('oauth_problem=parameter_absent%26' +
                        'oauth_parameters_absent%3DcallbackURL&oauth_problem_advice=' +
                        'You%20must%20include%20a%20callbackURL%20in%20your%20request%20for%20a%20token');
                    done();
                });

                spyOn(ModelA, 'isValidTimeStamp').andCallFake(function(){
                    return true;
                });

                initialize(req, res, next);
                session(req, res, next);
                ModelA.requestToken(req, res, function () {
                });
            });

        });
    });
});