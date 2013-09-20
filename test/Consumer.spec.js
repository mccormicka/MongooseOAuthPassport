'use strict';

/*jshint camelcase:false */
describe('Consumer Tests', function () {

//    var CONSUMER_KEY = '$2a$04$9WIDR8lZY/tKwFI8sBcYTulhp.z9AvJ6lMgLNXRvh8vOM9APM.zrG';
//    var CONSUMER_SECRET = '$2a$04$9WIDR8lZY/tKwFI8sBcYTuRMjA0SkURD2Bw9.DAZWnbiEWrHRZzEy';
//    var REQUEST_TOKEN = '$2a$04$.sx9IW2Ab0Is6DF.9AocceqcfnMN7S9qDEP294hZHUk.xBEzzr6ua';
//    var REQUEST_SECRET = '$2a$04$.sx9IW2Ab0Is6DF.9AocceC9rGc3RsoSpu8BG4L4PMP74XzvaesrS';

//    var http = require('http');
//    var reqProxy = http.IncomingMessage.prototype;
    var moment = require('moment');
    var oauthorize = require('oauthorize').createServer();
    var Passport = require('passport').Passport;
    var passport = new Passport();
    var mockgoose = require('Mockgoose');
    var mongoose = require('mongoose');
    mockgoose(mongoose);
    var db = mongoose.createConnection('mongodb://localhost:3001/Whatever');
    var Consumer = require('../lib/Consumer');
    var schema = new mongoose.Schema();
    //Add our OAuth Plugin
    schema.plugin(Consumer,
        {
            tableName: 'randomTableNameConsumer',
            passport: passport,
            oauthorize:oauthorize
        });

    var Model = db.model('randommodel', schema);

//    var initialize = passport.initialize();
//    var session = passport.session();
//    var next = function () {
//    };

    describe('Should', function () {
        it('Return valid if timestamp in range', function (done) {
            var time = moment().unix();
            var oneMinute = moment.duration(59, 'seconds');
            expect(Model.isValidTimeStamp(time, '1m')).toBe(true);
            expect(Model.isValidTimeStamp(moment().subtract(oneMinute).unix(), '1m')).toBe(true);
            done();

        });

        it('Return invalid if timestamp out of range', function (done) {
            var twoMinutes = moment.duration(61, 'seconds');
            var twoMinutesAgo = moment(moment()).subtract(twoMinutes).unix();
            expect(Model.isValidTimeStamp(twoMinutesAgo, '1m')).toBe(false);
            done();
        });
    });
});