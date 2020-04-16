var path = require('path');

var BUILD_TOOLS = path.join(process.env.SPLUNK_SOURCE, 'web', 'build_tools');
var appPageConfig = require(path.join(BUILD_TOOLS, 'profiles', 'common', 'namespacedAppPages.config'));
var appDir = path.join(__dirname, '..');

module.exports = function(options) {
    var  result = appPageConfig(appDir, 'splunk_instrumentation', options);
   
    return result
}
