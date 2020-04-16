const splunkConfig = require('splunk.config');

/**
 * The splunkd module will call this decorator function
 * with itself as the only argument.
 */
module.exports = function splunkdDecorator(splunkd) {
    splunkd.cached = splunkd.cached || {
        cache: {},

        /**
         * A cached version of splunkd.get that takes only a URL,
         * and always returns the same promise for the same URL.
         */
        get(url) {
            const cached = splunkd.cached.cache[url];

            if (cached) {
                return cached;
            }

            const result = splunkd.cached.cache[url] = splunkd.get(url);
            return result;
        },

        /**
         * Gets server info.
         */
        getServerInfo() {
            return this.get(splunkd.servicesUrl('server/info'));
        },

        /**
         * Gets user info.
         */
        getUserInfo() {
            return this.get(splunkd.servicesUrl('authentication/users/' + splunkConfig.USERNAME));
        },
    };
};
