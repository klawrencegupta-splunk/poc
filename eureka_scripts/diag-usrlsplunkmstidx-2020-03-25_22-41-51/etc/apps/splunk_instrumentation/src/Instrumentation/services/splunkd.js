var $ = require('jquery'),
    _ = require('underscore'),
    environment = require('Instrumentation/services/environment');

var splunkd = {};

// Public API
// ----------

splunkd.get = function (/* options | url, headers, data */) {
    var options = _normalizeRequestArguments.apply(this, arguments);
    return $.ajax(_.defaults(options, {
        type: 'GET'
    }));
};

splunkd.post = function (/* options | url, headers, data */) {
    var options = _normalizeRequestArguments.apply(this, arguments);
    return $.ajax(_.defaults(options, {
        type: 'POST'
    }));
};

splunkd.put = function (/* options | url, headers, data */) {
    var options = _normalizeRequestArguments.apply(this, arguments);
    return $.ajax(_.defaults(options, {
        type: 'PUT'
    }));
};

splunkd.patch = function (/* options | url, headers, data */) {
    var options = _normalizeRequestArguments.apply(this, arguments);
    return $.ajax(_.defaults(options, {
        type: 'PATCH'
    }));
};

splunkd.delete = function (/* options | url, headers, data */) {
    var options = _normalizeRequestArguments.apply(this, arguments);
    return $.ajax(_.defaults(options, {
        type: 'DELETE'
    }));
};

splunkd.servicesUrl = function (endpoint) {
    return _createServiceUrl(endpoint);
};

splunkd.servicesNsUrl = function (owner, app, endpoint) {
    return _createServiceUrl(endpoint, true, owner, app);
};

// Private Functions
// -----------------

var _createServiceUrl = function (endpoint, isNS, owner, app) {
    var application = environment.get('application'),
        root = application.get('root') ? '/' + application.get('root') : '',
        locale = '/' + application.get('locale'),
        serviceUrl = '/splunkd/__raw/services',
        url = root + locale + serviceUrl;

    if (isNS) {
        url += 'NS/' + (owner ? owner : '-') + '/' + (app ? app : '-');
    }
    return url + ((endpoint && endpoint[0] == '/') ? '' : '/') + (endpoint ? endpoint : '')
}

var _normalizeRequestArguments = function (url, headers, data) {
    if (typeof url === 'string') {
        return {
            url: _ensureOutputModeSet(url),
            headers: headers,
            data: data
        };
    } else if (typeof(url) === 'object') {
        var opt = url;
        return _.defaults({
            url: _ensureOutputModeSet(opt.url),
        }, opt);
    }
}

var _ensureOutputModeSet = function (url) {
    if (url.indexOf('output_mode') != -1) {
        return url;
    }

    if (url.indexOf('?') == -1) {
        return url + '?output_mode=json';
    } else {
        return url + '&output_mode=json';
    }
};

// Sub-component Decorators
// ------------------------

require('./splunkd.cached')(splunkd);
require('./splunkd.search')(splunkd);

module.exports = splunkd;
