var _ = require('underscore'),
    $ = require('jquery'),
    splunkConfig = require('splunk.config');

/**
 * The splunkd module will call this decorator function
 * with itself as the only argument.
 */
module.exports = function (splunkd) {
    splunkd.cached = splunkd.cached || {
        cache: {},

        /**
         * A cached version of splunkd.get that takes only a URL,
         * and always returns the same promise for the same URL.
         */
        get: function (url) {
            var cached = splunkd.cached.cache[url],
                result;

            if (cached) {
                return cached;
            }

            result = splunkd.cached.cache[url] = splunkd.get(url);
            return result;
        },

        /**
         * Gets server info.
         */
        getServerInfo: function () {
            return this.get(splunkd.servicesUrl('server/info'));
        },

        /**
         * Gets user info.
         */
        getUserInfo: function () {
            return this.get(splunkd.servicesUrl('authentication/users/' + splunkConfig.USERNAME));
        }
    };
};
