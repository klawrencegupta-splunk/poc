var style = require('./ExportModal.pcss'),
    _ = require('underscore'),
    $ = require('jquery'),
    Model = require('Instrumentation/framework/Model'),
    Component = require('Instrumentation/framework/Component'),
    constants = require('Instrumentation/constants'),
    ConfirmationModal = require('Instrumentation/views/controls/ConfirmationModal'),
    DocLink = require('Instrumentation/views/controls/DocLink'),
    bodyTemplate = require('contrib/text!./ExportModalBody.html'),
    TimeRange = require('models/shared/TimeRange'),
    TimeRangeDelegate = require('views/shared/delegates/ModalTimerangePicker'),
    DateRangeSelector = require('Instrumentation/views/controls/DateRangeSelector'),
    DataSendingService = require('Instrumentation/services/DataSendingService'),
    MessageService = require('Instrumentation/services/MessageService'),
    AlertMessage = require('Instrumentation/views/controls/AlertMessage');

var ExportModalBody = Component.extend({
    name: 'ExportModalBody',

    template: bodyTemplate,

    templateContext: function () {
        return {viewModel: this.options.viewModel};
    },

    initialize: function (opt) {
        Component.prototype.initialize.apply(this, arguments);
        this.options = this.options || opt;
        this.messageService = opt.messageService;
    },

    components: {
        dateRangeSelector: function () {
            this.dateRangeSelector = new DateRangeSelector({
                model: this.model,
                isPopup: false
            });
            return this.dateRangeSelector;
        },

        alertMessage: function () {
            return new AlertMessage({
                messageService: this.messageService
            });
        },

        exportDocLink: function () {
            return new DocLink({location: 'learnmore.instrumentation.export'});
        },
    }
});

var _super = ConfirmationModal;
module.exports = _super.extend({
    name: 'ExportModal',
    moduleId: module.id,

    titleTemplate: '<%= _("Export/Send Usage Data").t() %>',
    footerTemplate: '<a href="#" class="btn back modal-btn-back pull-left"><%= _("Back").t() %></a><button class="dismiss-button btn btn-other"><%= _("OK").t() %></button>',

    templateContext: function () {
        return {viewModel: this.viewModel};
    },

    events: _.extend({
        "click .dismiss-button": 'hide',
        "click .export-data-button": 'exportData',
        "click .send-data-button": 'sendData',
        "click .date-range-picker": 'showDateRangePopTart'
    }, ConfirmationModal.prototype.events),

    initialize: function (options) {
        this.dataSendingService = new DataSendingService();

        this.viewModel = new Model({
            sending: false,
            exporting: false
        });

        // If there is a built-in way to generate a fully initialized TimeRange,
        // we should be using that. For now, set up an "all time" range by default.
        this.timeRange = new TimeRange({
            earliest : '-30d@d',
            latest : 'now'
        });

        this.timeRange.on('applied', function() {
            if (this.timeRangeDelegate) {
                this.timeRangeDelegate.closeTimeRangePicker();
            }
        }, this);

        this.setupMessageService();

        this.bodyComponent = new ExportModalBody({
            model: this.timeRange,
            viewModel: this.viewModel,
            messageService: this.messageService
        });
        this.bodyComponent.on('afterRender', function() {
            this.prepareScrollModal = false;
            if (this.bodyComponent.dateRangeSelector){
                this.bodyComponent.dateRangeSelector = new DateRangeSelector({
                    model: this.timeRange,
                    isPopup: false
                });
            }
            if (this.timeRangeDelegate) {
                // Remove listeners from previous timeRangeDelegate.
                this.timeRangeDelegate.undelegateEvents();
                this.timeRangeDelegate.remove();
            }
            this.afterRender();
        }.bind(this));

        _super.prototype.initialize.apply(this, options);
    },

    afterRender: function(options) {
        // Prepare DateRangePicker
        var $body = this.$(ConfirmationModal.BODY_SELECTOR),
            $child = $body.children('div'),
            $modalBody = this.$('.export-modal-body'),
            dateRangeSelector = this.bodyComponent.dateRangeSelector;

        if (!this.prepareScrollModal && $modalBody.length && dateRangeSelector) {
            this.prepareScrollModal = true;
            $body.addClass('vis-area').removeClass(ConfirmationModal.BODY_CLASS);
            $child.addClass('slide-area');
            $modalBody.addClass(ConfirmationModal.BODY_CLASS);

            this.$visArea = this.$('.vis-area').eq(0);
            this.$slideArea = this.$('.slide-area').eq(0);
            this.$editSearchContent = this.$('.query-dialog-wrapper').eq(0);
            this.$timeRangePickerWrapper = this.$('.timerange-picker-wrapper').eq(0);
            this.$modalParent = this.$el;
            this.$('.btn.back').hide();

            $.when(dateRangeSelector.deferred).then(function() {
                this.$timeRangePickerWrapper.append(dateRangeSelector.timeRangePicker.render().el);
                this.timeRangeDelegate = new TimeRangeDelegate({
                    el: this.el,
                    $visArea: this.$visArea,
                    $slideArea: this.$slideArea,
                    $contentWrapper: this.$editSearchContent,
                    $timeRangePickerWrapper: this.$timeRangePickerWrapper,
                    $modalParent: this.$modalParent,
                    $timeRangePicker: dateRangeSelector.timeRangePicker.$el,
                    activateSelector: 'button.date-range-dropdown-button',
                    backButtonSelector: 'a.btn.back'
                });
            }.bind(this));
        }
    },

    setupMessageService: function () {
        this.messageService = new MessageService();
        this.on('hidden', function () {
            this.messageService.clear();
        })
    },

    toggleState: function(state, isEnabled, errorMessage, errorDetails) {
        if (!this.toggleStates) {
            this.toggleStates = [];
        }
        this.viewModel.set(state, isEnabled);
        var dateRangeButton = this.$('.date-range-dropdown-button');
        if (dateRangeButton.length) {
            if (isEnabled) {
                this.toggleStates.push(state);
                dateRangeButton.attr('disabled', 'disabled');
            }
            else {
                this.toggleStates.pop();
                if (this.toggleStates.length < 1) {
                    dateRangeButton.removeAttr('disabled');
                }
            }
        }
        if (errorMessage) {
            this.messageService.error(errorMessage, errorDetails);
        }
        else if (!isEnabled) {
            this.messageService.clear();
        }
    },

    exportData: function () {
        this.toggleState('exporting', true);
        this.getExportDataStrategy()(this.timeRange).
            done(function () {
                this.toggleState('exporting', false);
                this.messageService.clear();
            }.bind(this)).
            fail(function (reason) {
                var defaultMessage = constants.DATA_REPORTING_VALIDATION.ERROR_MESSAGE.DEFAULT;
                this.toggleState('exporting', false, reason.MESSAGE || defaultMessage.MESSAGE, reason.DETAILS || "");
            }.bind(this));
    },

    sendData: function () {
        this.toggleState('sending', true);
        this.getSendDataStrategy()(this.timeRange).
            done(function () {
                this.toggleState('sending', false);
                this.messageService.clear();
            }.bind(this)).
            fail(function (reason) {
                var defaultMessage = constants.DATA_REPORTING_VALIDATION.ERROR_MESSAGE.DEFAULT;
                this.toggleState('sending', false, reason.MESSAGE || defaultMessage.MESSAGE, reason.DETAILS || defaultMessage.DETAILS);
            }.bind(this));
    },

    getSendDataStrategy: function () {
        throw new Error("The send data strategy getter is supposed to be supplied by a subclass.");
    },

    getExportDataStrategy: function () {
        throw new Error("The export data strategy getter is supposed to be supplied by a subclass.");
    },

    trigger: function () {
        _super.prototype.trigger.apply(this, arguments);
    }
});
