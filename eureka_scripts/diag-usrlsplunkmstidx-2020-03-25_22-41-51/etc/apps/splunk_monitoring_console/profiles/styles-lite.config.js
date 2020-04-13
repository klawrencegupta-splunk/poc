var path = require('path');

var BUILD_TOOLS = path.join(process.env.SPLUNK_SOURCE, 'web', 'build_tools');
var mergeConfigs = require(path.join(BUILD_TOOLS, 'util', 'mergeConfigs'));
var bootsrapCssConfig = require(path.join(BUILD_TOOLS, 'profiles', 'css_base_lite.config'));

module.exports = mergeConfigs(bootsrapCssConfig, {
    output: {
        path: path.join(__dirname, '..', 'appserver', 'static', 'build', 'css')
    }
});
