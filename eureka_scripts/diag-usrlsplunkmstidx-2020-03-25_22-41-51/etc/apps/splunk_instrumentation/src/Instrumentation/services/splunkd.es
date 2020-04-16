const $ = require('jquery');
const _ = require('underscore');
const environment = require('splunk_instrumentation/Instrumentation/services/environment');
const splunkd = module.exports = {};

// Private Functions
// -----------------

const _ensureOutputModeSet = function (url) {
    if (url.indexOf('output_mode') !== -1) {
        return url;
    }

    if (url.indexOf('?') === -1) {
        return url + '?output_mode=json';
    }
    return url + '&output_mode=json';
};

const _normalizeRequestArguments = function (url, headers, data) {
    if (typeof url === 'string') {
        return {
            url: _ensureOutputModeSet(url),
            headers: headers,
            data: data,
        };
    } else if (typeof(url) === 'object') {
        const opt = url;
        return _.defaults({
            url: _ensureOutputModeSet(opt.url),
        }, opt);
    }
    throw new Error(`Unrecognized url argument type: ${typeof url}`);
};

/**
 * Request method generator.
 * Creates a function that triggers a jQuery.ajax call
 * after applying splunk-specific defaults to the request
 * options. The desired http method used for the method is
 * supplied as the only argument.
 */
const requestMethod = (method) => function request(/* options | url, headers, data */) {
    const options = _normalizeRequestArguments.apply(this, arguments);
    return $.ajax(_.defaults(options, {
        type: method,
    }));
};

// Public API
// ----------

splunkd.get = requestMethod('GET');
splunkd.post = requestMethod('POST');
splunkd.put = requestMethod('PUT');
splunkd.patch = requestMethod('PATCH');
splunkd.delete = requestMethod('DELETE');

splunkd.servicesUrl = function servicesUrl(endpoint) {
    return this.routes.splunkdRaw(`/services/${endpoint}`);
};

splunkd.servicesNsUrl = function servicesNsUrl(owner, app, endpoint) {
    return this.routes.splunkdNS(owner, app, endpoint);
};

// Sub-component Decorators
// ------------------------

require('./splunkd.cached')(splunkd);
require('./splunkd.search')(splunkd);
require('./splunkd.routes')(splunkd);

