'use strict';

module.exports = function Plugin(schema, options) {
    //Load up the RequestToken plugin
    schema.plugin(require('./OAuth'), options);

};