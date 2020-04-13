var Collection = require('Instrumentation/framework/Collection'),
    constants = require('Instrumentation/constants');

module.exports = Collection.extend({
    url: constants.INSTRUMENTATION_CONTROLLER_URL + ''
});
