'use strict';

/*jshint camelcase:false */
describe('Consumer Tests', function () {

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