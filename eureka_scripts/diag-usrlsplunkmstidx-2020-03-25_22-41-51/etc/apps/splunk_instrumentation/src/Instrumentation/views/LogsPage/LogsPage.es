require('./LogsPage.pcss');

const _ = require('underscore');
const Model = require('splunk_instrumentation/Instrumentation/framework/Model');
const Collection = require('splunk_instrumentation/Instrumentation/framework/Collection');
const constants = require('splunk_instrumentation/Instrumentation/constants');
const Component = require('splunk_instrumentation/Instrumentation/framework/Component');
const templateString = require('contrib/text!./LogsPage.html');
const MessageService = require('splunk_instrumentation/Instrumentation/services/MessageService');
const AlertMessage = require('splunk_instrumentation/Instrumentation/views/controls/AlertMessage');
const environment = require('splunk_instrumentation/Instrumentation/services/environment');
const TabBar = require('splunk_instrumentation/Instrumentation/views/controls/TabBar');
const InstrumentationService = require('splunk_instrumentation/Instrumentation/services/InstrumentationService');
const InstrumentationLog = require('./InstrumentationLog');
const instrumentationLinks = require('splunk_instrumentation/Instrumentation/services/instrumentationLinks');

module.exports = Component.extend({
    name: 'LogsPage',
    moduleId: module.id,

    template: templateString,

    components: {
        tabBar() {
            return new TabBar({
                collection: this.viewModel.get('tabs'),
            });
        },
        anonymousDataLogs() {
            return new InstrumentationLog({
                dataType: constants.DATA_TYPES.ANONYMOUS,
                messageService: this.messageService,
            });
        },
        licenseDataLogs() {
            return new InstrumentationLog({
                dataType: constants.DATA_TYPES.LICENSE,
                messageService: this.messageService,
            });
        },
        alertMessage() {
            return new AlertMessage({
                messageService: this.messageService,
            });
        },
    },

    initialize() {
        Component.prototype.initialize.apply(this, arguments);
        this.messageService = new MessageService();
        this.instrumentationService = new InstrumentationService();

        // So we can use them easily in the template
        this.instrumentationLinks = instrumentationLinks;
        this.constants = constants;
    },

    beforeFirstRender() {
        this.viewModel = new Model();

        this.viewModel.set('tabs', new Collection([
            new Model({
                label: _('Anonymized Data').t(),
                selected: false,
                id: constants.DATA_TYPES.ANONYMOUS,
            }),
            new Model({
                label: _('License Usage').t(),
                selected: false,
                id: constants.DATA_TYPES.LICENSE,
            }),
        ]));

        this.viewModel.get('tabs').on('change:selected', this.onChangeTabSelection.bind(this));
        this.setInitialTabSelection();
    },

    setInitialTabSelection() {
        let tabSelected = false;

        if (window.location.search && window.location.search.length > 0) {
            const querySegments = window.location.search.toLowerCase().split(/\?|&/);

            this.viewModel.get('tabs').each((tabModel) => {
                if (querySegments.indexOf(('dataType=' + tabModel.get('id')).toLowerCase()) > -1) {
                    tabSelected = true;
                    tabModel.set('selected', true);
                }
            });
        }

        if (!tabSelected) {
            this.viewModel.get('tabs').at(0).set('selected', true);
        }
    },

    onChangeTabSelection(tabModel) {
        if (tabModel.get('selected')) {
            const tabId = tabModel.get('id');
            this.viewModel.set('selectedTabId', tabId);
            environment.get('router').navigate(
                location.pathname + '?dataType=' + tabId.toLowerCase(),
                {
                    replace: true,
                }
            );
        }
    },
});
