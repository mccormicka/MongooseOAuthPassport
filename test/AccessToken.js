'use strict';

/*jshint camelcase:false */
describe('AccessToken Tests', function () {

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
            url: '/oauth/request_token',
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
                'realm="http://localhost:3001/oauth/access_token",' +
                'oauth_consumer_key="%242a%2404%24x2jefs5s63LvWzU9i.pReOhXuTqrIopguZgad6g9BUZbOrDuVdVom",' +
                'oauth_token="%242a%2404%24mcn4Uf7%2FE.p6hEnEh1xpBOmkvMcHOEYxdCVUA3HHSocjv6oqUGWzO",' +
                'oauth_signature_method="HMAC-SHA1",' +
                'oauth_timestamp="1379120506",' +
                'oauth_nonce="TXaNnz",oauth_version="1.0",' +
                'oauth_callback="blog%2Fawesome%3Dfullofit",' +
                'oauth_signature="GGEG%2BP2%2Fj504Qkk3ucVQ5VkqGVM%3D"',
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
            console.log('Created model', err, result);
            result.createRandomTableNameConsumer(function (err, result) {
                result.key = '$2a$04$x2jefs5s63LvWzU9i.pReOhXuTqrIopguZgad6g9BUZbOrDuVdVom';
                result.secret = '$2a$04$x2jefs5s63LvWzU9i.pReOKDGTFptcIFt2OLp5HS68VnlWYVJSmMW';
                result.save(done);
            });
        });
    });

    xdescribe('SHOULD', function () {

        it('Add a accessToken method to our model', function (done) {
            expect(typeof Model.accessToken === 'function').toBe(true);
            done();
        });

        describe('Unauthorized', function () {

            it('Respond unauthorized if no params sent', function (done) {
                var req = new Request();
                var res = new Response();
                spyOn(res, 'end').andCallFake(function (value) {
                    expect(value).toBe('Unauthorized');
                    done();
                });
                Model.requestToken(req, res, function () {
                });

            });

            describe('Consumer key', function () {
                it('Respond unauthorized if no consumer key params sent', function (done) {
                    var req = new Request();
                    var res = new Response();
                    req.headers = new Headers();
                    req.headers.authorization = 'OAuth ' +
                        'realm="http://localhost:3001/oauth/access_token",' +
                        'oauth_token="%242a%2404%24mcn4Uf7%2FE.p6hEnEh1xpBOmkvMcHOEYxdCVUA3HHSocjv6oqUGWzO",' +
                        'oauth_signature_method="HMAC-SHA1",' +
                        'oauth_timestamp="1379120506",' +
                        'oauth_nonce="TXaNnz",oauth_version="1.0",' +
                        'oauth_callback="blog%2Fawesome%3Dfullofit",' +
                        'oauth_signature="GGEG%2BP2%2Fj504Qkk3ucVQ5VkqGVM%3D"';
                    spyOn(res, 'setHeader').andCallFake(function () {
                        expect(arguments[1]).toEqual([ 'OAuth realm="Clients", oauth_problem="parameter_absent"' ]);
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

                it('Respond unauthorized if invalid consumer key params sent', function (done) {
                    var req = new Request();
                    var res = new Response();
                    req.headers = new Headers();
                    req.headers.authorization = 'OAuth ' +
                        'oauth_consumer_key="%242a%2404%24x2jefs5s63LvWzU9i.pReOhXuTqrIopguZgad6g9BUZbOrDuVdVominvalid",' +
                        'realm="http://localhost:3001/oauth/access_token",' +
                        'oauth_token="%242a%2404%24mcn4Uf7%2FE.p6hEnEh1xpBOmkvMcHOEYxdCVUA3HHSocjv6oqUGWzO",' +
                        'oauth_signature_method="HMAC-SHA1",' +
                        'oauth_timestamp="1379120506",' +
                        'oauth_nonce="TXaNnz",oauth_version="1.0",' +
                        'oauth_callback="blog%2Fawesome%3Dfullofit",' +
                        'oauth_signature="GGEG%2BP2%2Fj504Qkk3ucVQ5VkqGVM%3D"';
                    spyOn(res, 'setHeader').andCallFake(function () {
                        expect(arguments[1]).toEqual([ 'OAuth realm="Clients", oauth_problem="consumer_key_rejected"' ]);
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

                it('Respond unauthorized if invalid token key params sent', function (done) {
                    var req = new Request();
                    var res = new Response();
                    req.headers = new Headers();
                    req.headers.authorization = 'OAuth ' +
                        'realm="http://localhost:3001/oauth/access_token",' +
                        'oauth_consumer_key="%242a%2404%24x2jefs5s63LvWzU9i.pReOhXuTqrIopguZgad6g9BUZbOrDuVdVom",' +
                        'oauth_token="%242a%2404%24mcn4Uf7%2FE.p6hEnINVALIDEh1xpBOmkvMcHOEYxdCVUA3HHSocjv6oqUGWzO",' +
                        'oauth_signature_method="HMAC-SHA1",' +
                        'oauth_timestamp="1379120506",' +
                        'oauth_nonce="TXaNnz",oauth_version="1.0",' +
                        'oauth_callback="blog%2Fawesome%3Dfullofit",' +
                        'oauth_signature="GGEG%2BP2%2Fj504Qkk3ucVQ5VkqGVM%3D"';
                    spyOn(res, 'setHeader').andCallFake(function () {
                        expect(arguments[1]).toEqual([ 'OAuth realm="Clients", oauth_problem="consumer_key_rejected"' ]);
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

            describe('OAuth signature', function () {
                it('Respond unauthorized if invalid signature params sent', function (done) {
                    var req = new Request();
                    var res = new Response();
                    req.headers = new Headers();
                    req.headers.authorization = 'OAuth ' +
                        'realm="http://localhost:3001/oauth/access_token",' +
                        'oauth_consumer_key="%242a%2404%24x2jefs5s63LvWzU9i.pReOhXuTqrIopguZgad6g9BUZbOrDuVdVom",' +
                        'oauth_token="%242a%2404%24mcn4Uf7%2FE.p6hEnEh1xpBOmkvMcHOEYxdCVUA3HHSocjv6oqUGWzO",' +
                        'oauth_signature_method="HMAC-SHA1",' +
                        'oauth_timestamp="1379120506",' +
                        'oauth_nonce="TXaNnz",oauth_version="1.0",' +
                        'oauth_callback="blog%2Fawesome%3Dfullofit",' +
                        'oauth_signature="invalidGGEG%2BP2%2Fj504Qkk3ucVQ5VkqGVM%3D"';
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
                initialize(req, res, next);
                session(req, res, next);
                Model.requestToken(req, res, function () {
                });
            });
        });

    });
});