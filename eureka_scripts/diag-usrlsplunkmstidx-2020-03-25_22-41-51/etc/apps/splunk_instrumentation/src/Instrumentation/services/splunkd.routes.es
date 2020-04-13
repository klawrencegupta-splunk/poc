const splunkRoute = require('uri/route');
const environment = require('splunk_instrumentation/Instrumentation/services/environment');

module.exports = function splunkdDecorator(splunkd) {
    splunkd.routes = {
        /**
         * @param value: Value to get from the application model.
         * @returns {*} Value from application model.
         */
        _getFromApp(value) {
            return environment.get('application').get(value);
        },

        // Url Helpers from route.js.
        // Automatically prepends root and locale.
        // Also fixes any occurrence of // to /
        encodeRoot(path) {
            return (splunkRoute.encodeRoot(
                this._getFromApp('root'),
                this._getFromApp('locale')) + path
            ).replace('//', '/');
        },
        manager(page, options) {
            return splunkRoute.manager(
                this._getFromApp('root'),
                this._getFromApp('locale'),
                this._getFromApp('app'),
                page,
                { data: options }
            ).replace('//', '/');
        },
        splunkdRaw(path) {
            return (splunkRoute.splunkdRaw(
                this._getFromApp('root'),
                this._getFromApp('locale')
            ) + path).replace('//', '/');
        },
        splunkdNS(owner, app, path) {
            return splunkRoute.splunkdNS(
                this._getFromApp('root'),
                this._getFromApp('locale'),
                owner || '-',
                app || '',
                path
            ).replace('//', '/');
        },
    };
};

