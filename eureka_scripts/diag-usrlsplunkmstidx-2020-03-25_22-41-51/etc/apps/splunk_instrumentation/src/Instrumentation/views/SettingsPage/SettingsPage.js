var style = require('./SettingsPage.pcss'),
    Backbone = require('backbone'),
    _ = require('underscore'),
    View = require('Instrumentation/framework/View'),
    Component = require('Instrumentation/framework/Component'),
    templateString = require('contrib/text!./SettingsPage.html'),
    InstrumentationStatus = require('Instrumentation/models/InstrumentationStatus'),
    EnableDisableToggle = require('Instrumentation/views/controls/EnableDisableToggle'),
    DocLink = require('Instrumentation/views/controls/DocLink'),
    AlertMessage = require('Instrumentation/views/controls/AlertMessage'),
    MessageService = require('Instrumentation/services/MessageService'),
    ConfirmationModal = require('Instrumentation/views/controls/ConfirmationModal'),
    AnonymousExportModal = require('./AnonymousExportModal'),
    LicenseExportModal = require('./LicenseExportModal'),
    LicenseDataOptOutModal = require('./LicenseDataOptOutModal'),
    environment = require('Instrumentation/services/environment'),
    constants = require('Instrumentation/constants'),
    InstrumentationService = require('Instrumentation/services/InstrumentationService'),
    time = require('Instrumentation/services/time');

var _super = Component;
module.exports = _super.extend({
    name: 'SettingsPage',

    moduleId: module.id,

    template: templateString,

    events: {
        'click button.export-anonymous-data': 'exportAnonymousData',
        'click button.export-license-data': 'exportLicenseData'
    },

    initialize: function () {
        _super.prototype.initialize.apply(this, arguments);

        this.model = new InstrumentationStatus();
        this.instrumentationService = new InstrumentationService();
        this.messageService = new MessageService();

        // Modals aren't part of the template. So we'll save them off to manually
        // hide & show them later.
        this.modals = {
            confirmLicenseDataOptOutModal: new LicenseDataOptOutModal().render(),
            anonymousDataExportModal: new AnonymousExportModal().render(),
            licenseDataExportModal: new LicenseExportModal().render()
        };

        // So we can use them in the template
        this.constants = constants;
        this.time = time;
        this.router = environment.get('router');

        this.refresh();
    },

    components: {

        anonymousDataDocLink: function () {
            return new DocLink({location: 'learnmore.performance.instrumentation'});
        },

        licenseDataDocLink: function () {
            return new DocLink({location: 'learnmore.usage.instrumentation'});
        },

        anonymousDataToggle: function () {
            return new EnableDisableToggle({
                model: this.model.get('anonymous_usage_data'),
                attribute: 'enabled',

                onEnabled: function (done) {
                    this.messageService.clear();
                    this.instrumentationService.updateGeneralStanza({sendAnonymizedUsage: true})
                        .then(this.refresh.bind(this))
                        .then(done)
                        .fail(function () {
                            this.displayServerError();
                            done();
                        }.bind(this));
                }.bind(this),

                onDisabled: function (done) {
                    this.messageService.clear();
                    this.instrumentationService.updateGeneralStanza({sendAnonymizedUsage: false})
                        .then(this.refresh.bind(this))
                        .then(done)
                        .fail(function () {
                            this.displayServerError();
                            done();
                        }.bind(this));
                }.bind(this)
            });
        },

        licenseDataToggle: function () {
            var toggle = new EnableDisableToggle({
                model: this.model.get('license_usage_data'),
                attribute: 'enabled',

                onEnabled: function (done) {
                    this.messageService.clear();
                    this.instrumentationService.updateGeneralStanza({sendLicenseUsage: true})
                        .then(this.refresh.bind(this))
                        .then(done)
                        .fail(function () {
                            this.displayServerError();
                            done();
                        }.bind(this));
                }.bind(this),

                onDisabled: function (done) {
                    this.messageService.clear();
                    this.modals.confirmLicenseDataOptOutModal.show()
                        .then(function () {
                            this.instrumentationService.updateGeneralStanza({sendLicenseUsage: false})
                                .then(this.refresh.bind(this))
                                .then(done)
                                .fail(function () {
                                    this.displayServerError();
                                    done();
                                }.bind(this))
                        }.bind(this)).fail(function() {
                            toggle.viewModel.set('pending', false);
                            toggle.enableToggle();
                        }.bind(this));
                }.bind(this)
            });
            return toggle;
        },

        alertMessage: function () {
            return new AlertMessage({
                messageService: this.messageService
            });
        }
    },

    exportAnonymousData: function () {
        this.modals.anonymousDataExportModal.show({dataType: constants.DATA_TYPES.ANONYMOUS});
    },

    exportLicenseData: function () {
        this.modals.licenseDataExportModal.show({dataType: constants.DATA_TYPES.LICENSE});
    },

    refresh: function (done) {
        return this.model.fetch().
            done((typeof(done) === 'function') ? done : function () {}).
            fail(this.displayServerError.bind(this));
    },

    displayServerError: function (exception, message) {
        message = message || constants.DEFAULT_SERVER_ERROR;
        this.messageService.error(message, exception);
    },

    remove: function () {
        Object.keys(this.modals).forEach(function (modal) {
            this.modals[modal].remove();
        }.bind(this));
        return _super.prototype.remove.apply(this, arguments);
    }
});
