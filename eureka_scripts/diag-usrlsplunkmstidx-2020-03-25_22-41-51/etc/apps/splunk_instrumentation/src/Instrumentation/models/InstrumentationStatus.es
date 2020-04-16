const $ = require('jquery');
const Model = require('splunk_instrumentation/Instrumentation/framework/Model');
const InstrumentationService =
    require('splunk_instrumentation/Instrumentation/services/InstrumentationService');

module.exports = Model.extend({
    constructor() {
        this.attributes = {
            anonymous_usage_data: new Model(),
            license_usage_data: new Model(),
        };
    },

    fetch(...args) {
        if (args.length > 0) {
            throw new Error('The InstrumentationStatus model does not support any options');
        }

        const service = new InstrumentationService();
        const deferreds = [];

        deferreds.push(service.getGeneralStanza());
        deferreds.push(service.get30DayReportingErrorCounts());
        deferreds.push(service.getLastSuccessfulReportTimes());

        // Return the deferred in case the client wants to wait.
        return $.when.apply($, deferreds).then((
            generalStanza,
            errorCounts,
            reportTimes
        ) => {
            const anonymousUsageModel = this.get('anonymous_usage_data');
            const licenseUsageModel = this.get('license_usage_data');
            const generalStanzaContent = generalStanza.entry[0].content;

            let optInIsUpToDate = true;
            if (typeof generalStanzaContent.optInVersion === 'number') {
                if (typeof generalStanzaContent.optInVersionAcknowledged === 'number') {
                    optInIsUpToDate = generalStanzaContent.optInVersionAcknowledged >= generalStanzaContent.optInVersion;
                } else {
                    optInIsUpToDate = false;
                }
            }

            anonymousUsageModel.set('enabled', optInIsUpToDate ? generalStanzaContent.sendAnonymizedUsage : false);
            anonymousUsageModel.set('last_sent', (reportTimes.latest_anonymous_send_time ?
                this.formatDateString(reportTimes.latest_anonymous_send_time) :
                null
            ));
            anonymousUsageModel.set('30_day_error_count', errorCounts.anonymous_errors);

            licenseUsageModel.set('enabled', optInIsUpToDate ? generalStanzaContent.sendLicenseUsage : false);
            licenseUsageModel.set('last_sent', (reportTimes.latest_license_send_time ?
                this.formatDateString(reportTimes.latest_license_send_time) :
                null
            ));
            licenseUsageModel.set('30_day_error_count', errorCounts.license_errors);

            return this;
        });
    },

    formatDateString(date) {
        return ('YEAR-MONTH-DAY'.
            replace('YEAR', date.getFullYear()).
            replace('MONTH', (`0${date.getMonth() + 1}`).slice(-2)).
            replace('DAY', (`0${date.getDate()}`).slice(-2))
        );
    },
});

