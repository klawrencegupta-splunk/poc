var style = require('./LogsPage.pcss'),
    Backbone = require('backbone'),
    _ = require('underscore'),
    Model = require('Instrumentation/framework/Model'),
    Collection = require('Instrumentation/framework/Collection'),
    constants = require('Instrumentation/constants'),
    Component = require('Instrumentation/framework/Component'),
    templateString = require('contrib/text!./LogsPage.html'),
    DocLink = require('Instrumentation/views/controls/DocLink'),
    MessageService = require('Instrumentation/services/MessageService'),
    AlertMessage = require('Instrumentation/views/controls/AlertMessage'),
    environment = require('Instrumentation/services/environment'),
    TabBar = require('Instrumentation/views/controls/TabBar'),
    InstrumentationService = require('Instrumentation/services/InstrumentationService'),
    InstrumentationLog = require('./InstrumentationLog'),
    environment = require('Instrumentation/services/environment');

module.exports = Component.extend({
    name: 'LogsPage',
    moduleId: module.id,

    template: templateString,

    components: {
        tabBar: function () {
            return new TabBar({
                collection: this.viewModel.get('tabs')
            });
        },
        anonymousDataLogs: function () {
            return new InstrumentationLog({
                dataType: constants.DATA_TYPES.ANONYMOUS,
                messageService: this.messageService
            });
        },
        licenseDataLogs: function () {
            return new InstrumentationLog({
                dataType: constants.DATA_TYPES.LICENSE,
                messageService: this.messageService
            });
        },
        alertMessage: function () {
            return new AlertMessage({
                messageService: this.messageService
            });
        }
    },

    initialize: function () {
        Component.prototype.initialize.apply(this, arguments);
        this.messageService = new MessageService();
        this.instrumentationService = new InstrumentationService();

        // So we can use them easily in the template
        this.router = environment.get('router');
        this.constants = constants;
    },

    beforeFirstRender: function () {
        this.viewModel = new Model();

        this.viewModel.set('tabs', new Collection([
            new Model({
                label: _('Anonymized Data').t(),
                selected: false,
                id: constants.DATA_TYPES.ANONYMOUS
            }),
            new Model({
                label: _('License Usage').t(),
                selected: false,
                id: constants.DATA_TYPES.LICENSE
            })
        ]));

        this.viewModel.get('tabs').on('change:selected', this.onChangeTabSelection.bind(this));
        this.setInitialTabSelection();
    },

    setInitialTabSelection: function () {
        var tabSelected = false;

        if (window.location.search && window.location.search.length > 0) {
            var querySegments = window.location.search.toLowerCase().split(/\?|&/);

            this.viewModel.get('tabs').each(function (tabModel) {
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

    onChangeTabSelection: function (tabModel) {
        if (tabModel.get('selected')) {
            var tabId = tabModel.get('id');
            this.viewModel.set('selectedTabId', tabId);
            environment.get('router').navigate(
                location.pathname + '?dataType=' + tabId.toLowerCase(),
                {
                    replace: true
                }
            );
        }
    }
});
