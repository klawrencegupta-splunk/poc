const Collection = require('splunk_instrumentation/Instrumentation/framework/Collection');
const constants = require('splunk_instrumentation/Instrumentation/constants');

module.exports = Collection.extend({
    url: constants.INSTRUMENTATION_CONTROLLER_URL,
});
