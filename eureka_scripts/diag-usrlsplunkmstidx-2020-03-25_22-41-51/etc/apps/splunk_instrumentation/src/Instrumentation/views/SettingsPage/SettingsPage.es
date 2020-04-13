require('./SettingsPage.pcss');
const _ = require('underscore');
const Component = require('splunk_instrumentation/Instrumentation/framework/Component');
const templateString = require('contrib/text!./SettingsPage.html');
const InstrumentationStatus = require('splunk_instrumentation/Instrumentation/models/InstrumentationStatus');
const EnableDisableToggle = require('splunk_instrumentation/Instrumentation/views/controls/EnableDisableToggle');
const DocLink = require('splunk_instrumentation/Instrumentation/views/controls/DocLink');
const AlertMessage = require('splunk_instrumentation/Instrumentation/views/controls/AlertMessage');
const MessageService = require('splunk_instrumentation/Instrumentation/services/MessageService');
const AnonymousExportModal = require('./AnonymousExportModal');
const LicenseExportModal = require('./LicenseExportModal');
const LicenseDataOptOutModal = require('./LicenseDataOptOutModal');
const environment = require('splunk_instrumentation/Instrumentation/services/environment');
const constants = require('splunk_instrumentation/Instrumentation/constants');
const InstrumentationService = require('splunk_instrumentation/Instrumentation/services/InstrumentationService');
const instrumentationLinks = require('splunk_instrumentation/Instrumentation/services/instrumentationLinks');
const time = require('splunk_instrumentation/Instrumentation/services/time');

const _super = Component;
module.exports = _super.extend({
    name: 'SettingsPage',

    moduleId: module.id,

    template: templateString,

    events: {
        'click button.export-anonymous-data': 'exportAnonymousData',
        'click button.export-license-data': 'exportLicenseData',
    },

    initialize() {
        _super.prototype.initialize.apply(this, arguments);

        this.model = new InstrumentationStatus();
        this.instrumentationService = new InstrumentationService();
        this.messageService = new MessageService();

        // Modals aren't part of the template. So we'll save them off to manually
        // hide & show them later.
        this.modals = {
            confirmLicenseDataOptOutModal: new LicenseDataOptOutModal().render(),
            anonymousDataExportModal: new AnonymousExportModal().render(),
            licenseDataExportModal: new LicenseExportModal().render(),
        };

        // So we can use them in the template
        this.constants = constants;
        this.time = time;
        this.instrumentationLinks = instrumentationLinks;

        this.refresh();
    },

    components: {

        anonymousDataDocLink() {
            return new DocLink({ location: 'learnmore.performance.instrumentation' });
        },

        licenseDataDocLink() {
            return new DocLink({ location: 'learnmore.usage.instrumentation' });
        },

        anonymousDataToggle() {
            return new EnableDisableToggle({
                model: this.model.get('anonymous_usage_data'),
                attribute: 'enabled',
                onEnabled: (done) => {
                    this.updateSettings({sendAnonymizedUsage: true}, done);
                },
                onDisabled: (done) => {
                    this.updateSettings({sendAnonymizedUsage: false}, done);
                },
            });
        },

        licenseDataToggle() {
            const toggle = new EnableDisableToggle({
                model: this.model.get('license_usage_data'),
                attribute: 'enabled',
                onEnabled: (done) => {
                    this.updateSettings({ sendLicenseUsage: true }, done);
                },
                onDisabled: (done) => {
                    this.modals.confirmLicenseDataOptOutModal.show()
                        .then(() => {
                            return this.updateSettings({ sendLicenseUsage: false }, done);
                        }).fail(() => {
                            done();
                        });
                },
            });
            return toggle;
        },

        alertMessage() {
            return new AlertMessage({
                messageService: this.messageService,
            });
        },
    },

    updateSettings(settings, done) {
        const previousSettings = {
            sendAnonymizedUsage: this.model.get('anonymous_usage_data').get('enabled'),
            sendAnonymizedWebAnalytics: this.model.get('anonymous_usage_data').get('enabled'),
            sendLicenseUsage: this.model.get('license_usage_data').get('enabled')
        };

        const newSettings = _.extend({}, previousSettings, settings);

        // One toggle on the UI controls both flags, so make sure we're setting both together
        if (settings.hasOwnProperty('sendAnonymizedUsage')) {
            newSettings.sendAnonymizedWebAnalytics = settings.sendAnonymizedUsage;
        }

        this.messageService.clear();
        const promise = this.instrumentationService.updateGeneralStanza(newSettings);
        return this.awaitServerResponse(promise, done);
    },

    exportAnonymousData() {
        this.modals.anonymousDataExportModal.show({ dataType: constants.DATA_TYPES.ANONYMOUS });
    },

    exportLicenseData() {
        this.modals.licenseDataExportModal.show({ dataType: constants.DATA_TYPES.LICENSE });
    },

    refresh(done) {
        return this.model.fetch().
            done(this.optionalFunction(done)).
            fail(this.displayServerError.bind(this));
    },

    displayServerError(exception, message = constants.DEFAULT_SERVER_ERROR) {
        this.messageService.error(message, exception);
    },

    remove() {
        Object.keys(this.modals).forEach((modal) => {
            this.modals[modal].remove();
        });
        return _super.prototype.remove.apply(this, arguments);
    },

    /**
     * Performs the common response handling logic for
     * communicating with the server.
     */
    awaitServerResponse(promise, done) {
        let optionalDoneFunction = this.optionalFunction(done);

        return promise.then(() => this.refresh()).
            then(optionalDoneFunction).fail(() => {
                this.displayServerError();
                optionalDoneFunction();
            });
    },

    /**
     * Returns the `fn` parameter if it is a function,
     * otherwise returns a no-op function that can safely
     * be called instead.
     */
    optionalFunction(fn) {
        return (typeof fn === 'function' ? fn : () => {});
    }
});
