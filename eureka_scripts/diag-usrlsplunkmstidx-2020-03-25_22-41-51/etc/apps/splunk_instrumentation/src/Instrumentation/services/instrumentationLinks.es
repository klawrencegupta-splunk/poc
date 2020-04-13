const splunkd = require('splunk_instrumentation/Instrumentation/services/splunkd');

module.exports = {
    get settingsPage() {
        return splunkd.routes.manager('instrumentation_index');
    },
    get anonymousDataLogs() {
        return splunkd.routes.manager('instrumentation_logs', { dataType: 'anonymous' });
    },
    get licenseDataLogs() {
        return splunkd.routes.manager('instrumentation_logs', { dataType: 'license' });
    },
};

