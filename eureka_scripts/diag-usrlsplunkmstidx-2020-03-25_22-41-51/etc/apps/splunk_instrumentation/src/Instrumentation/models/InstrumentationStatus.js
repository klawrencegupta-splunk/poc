var _ = require('underscore'),
    moment = require('moment'),
    Model = require('Instrumentation/framework/Model'),
    constants = require('Instrumentation/constants'),
    InstrumentationService = require('Instrumentation/services/InstrumentationService');

module.exports = Model.extend({
    constructor: function () {
        this.attributes = {
            anonymous_usage_data: new Model(),
            license_usage_data: new Model()
        }
    },

    fetch: function () {
        if (arguments.length > 0) {
            throw new Error("The InstrumentationStatus model does not support any options");
        }

        var service = new InstrumentationService();
            deferreds = [];

        deferreds.push(service.getGeneralStanza());
        deferreds.push(service.get30DayReportingErrorCounts());
        deferreds.push(service.getLastSuccessfulReportTimes());

        // Return the deferred in case the client wants to wait.
        return $.when.apply($, deferreds).then(function (
            generalStanza,
            errorCounts,
            reportTimes
        ) {
            var anonymousUsageModel = this.get('anonymous_usage_data'),
                licenseUsageModel = this.get('license_usage_data'),
                generalStanzaContent = generalStanza.entry[0].content;

            anonymousUsageModel.set('enabled', generalStanzaContent.sendAnonymizedUsage);
            anonymousUsageModel.set('last_sent', (reportTimes.latest_anonymous_send_time ?
                this.formatDateString(reportTimes.latest_anonymous_send_time) :
                null
            ));
            anonymousUsageModel.set('30_day_error_count', errorCounts.anonymous_errors);

            licenseUsageModel.set('enabled', generalStanzaContent.sendLicenseUsage);
            licenseUsageModel.set('last_sent', (reportTimes.latest_license_send_time ?
                this.formatDateString(reportTimes.latest_license_send_time) :
                null
            ));
            licenseUsageModel.set('30_day_error_count', errorCounts.license_errors);

            return this;
        }.bind(this));
    },

    formatDateString: function (date) {
        return ("YEAR-MONTH-DAY".
            replace('YEAR', date.getFullYear()).
            replace('MONTH', ('0' + (date.getMonth() + 1)).slice(-2)).
            replace('DAY', ('0' + date.getDate()).slice(-2))
        );
    }
});
