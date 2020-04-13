require('./ExportModal.pcss');
const _ = require('underscore');
const $ = require('jquery');
const Model = require('splunk_instrumentation/Instrumentation/framework/Model');
const Component = require('splunk_instrumentation/Instrumentation/framework/Component');
const constants = require('splunk_instrumentation/Instrumentation/constants');
const ConfirmationModal = require('splunk_instrumentation/Instrumentation/views/controls/ConfirmationModal');
const DocLink = require('splunk_instrumentation/Instrumentation/views/controls/DocLink');
const bodyTemplate = require('contrib/text!./ExportModalBody.html');
const TimeRange = require('models/shared/TimeRange');
const TimeRangeDelegate = require('views/shared/delegates/ModalTimerangePicker');
const DateRangeSelector = require('splunk_instrumentation/Instrumentation/views/controls/DateRangeSelector');
const DataSendingService = require('splunk_instrumentation/Instrumentation/services/DataSendingService');
const MessageService = require('splunk_instrumentation/Instrumentation/services/MessageService');
const AlertMessage = require('splunk_instrumentation/Instrumentation/views/controls/AlertMessage');

const ExportModalBody = Component.extend({
    name: 'ExportModalBody',

    template: bodyTemplate,

    templateContext() {
        return { viewModel: this.options.viewModel };
    },

    initialize(opt) {
        Component.prototype.initialize.apply(this, arguments);
        this.options = this.options || opt;
        this.messageService = opt.messageService;
    },

    components: {
        dateRangeSelector() {
            this.dateRangeSelector = new DateRangeSelector({
                model: this.model,
                isPopup: false,
            });
            return this.dateRangeSelector;
        },

        alertMessage() {
            return new AlertMessage({
                messageService: this.messageService,
            });
        },

        exportDocLink() {
            return new DocLink({ location: 'learnmore.instrumentation.export' });
        },
    },
});

const _super = ConfirmationModal;
module.exports = _super.extend({
    name: 'ExportModal',
    moduleId: module.id,

    titleTemplate: '<%= _("Export/Send Usage Data").t() %>',
    footerTemplate: `<a href="#" class="btn back modal-btn-back pull-left"><%= _("Back").t() %></a>
        <button class="dismiss-button btn btn-other"><%= _("OK").t() %></button>`,

    templateContext() {
        return { viewModel: this.viewModel };
    },

    events: _.extend({
        'click .dismiss-button': 'hide',
        'click .export-data-button': 'exportData',
        'click .send-data-button': 'sendData',
        'click .date-range-picker': 'showDateRangePopTart',
    }, ConfirmationModal.prototype.events),

    initialize(options) {
        this.dataSendingService = new DataSendingService();

        this.viewModel = new Model({
            sending: false,
            exporting: false,
        });

        // If there is a built-in way to generate a fully initialized TimeRange,
        // we should be using that. For now, set up an "all time" range by default.
        this.timeRange = new TimeRange({
            earliest: '-30d@d',
            latest: 'now',
        });

        this.timeRange.on('applied', function () {
            if (this.timeRangeDelegate) {
                this.timeRangeDelegate.closeTimeRangePicker();
            }
        }, this);

        this.setupMessageService();

        this.bodyComponent = new ExportModalBody({
            model: this.timeRange,
            viewModel: this.viewModel,
            messageService: this.messageService,
        });
        this.bodyComponent.on('afterRender', () => {
            this.prepareScrollModal = false;
            if (this.bodyComponent.dateRangeSelector) {
                this.bodyComponent.dateRangeSelector = new DateRangeSelector({
                    model: this.timeRange,
                    isPopup: false,
                });
            }
            if (this.timeRangeDelegate) {
                // Remove listeners from previous timeRangeDelegate.
                this.timeRangeDelegate.undelegateEvents();
                this.timeRangeDelegate.remove();
            }
            this.afterRender();
        });

        _super.prototype.initialize.apply(this, options);
    },

    afterRender() {
        // Prepare DateRangePicker
        const $body = this.$(ConfirmationModal.BODY_SELECTOR);
        const $child = $body.children('div');
        const $modalBody = this.$('.export-modal-body');
        const dateRangeSelector = this.bodyComponent.dateRangeSelector;

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

            $.when(dateRangeSelector.deferred).then(() => {
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
                    backButtonSelector: 'a.btn.back',
                });
            });
        }
    },

    setupMessageService() {
        this.messageService = new MessageService();
        this.on('hidden', function () {
            this.messageService.clear();
        });
    },

    toggleState(state, isEnabled, errorMessage, errorDetails) {
        if (!this.toggleStates) {
            this.toggleStates = [];
        }
        this.viewModel.set(state, isEnabled);
        const dateRangeButton = this.$('.date-range-dropdown-button');
        if (dateRangeButton.length) {
            if (isEnabled) {
                this.toggleStates.push(state);
                dateRangeButton.attr('disabled', 'disabled');
            } else {
                this.toggleStates.pop();
                if (this.toggleStates.length < 1) {
                    dateRangeButton.removeAttr('disabled');
                }
            }
        }
        if (errorMessage) {
            this.messageService.error(errorMessage, errorDetails);
        } else if (!isEnabled) {
            this.messageService.clear();
        }
    },

    exportData() {
        this.toggleState('exporting', true);
        this.getExportDataStrategy()(this.timeRange).
            done(() => {
                this.toggleState('exporting', false);
                this.messageService.clear();
            }).
            fail((reason) => {
                const defaultMessage = constants.DATA_REPORTING_VALIDATION.ERROR_MESSAGE.DEFAULT;
                this.toggleState(
                    'exporting',
                    false,
                    reason.MESSAGE || defaultMessage.MESSAGE,
                    reason.DETAILS || "");
            });
    },

    sendData() {
        this.toggleState('sending', true);
        this.getSendDataStrategy()(this.timeRange).
            done(() => {
                this.toggleState('sending', false);
                this.messageService.clear();
            }).
            fail((reason) => {
                const defaultMessage = constants.DATA_REPORTING_VALIDATION.ERROR_MESSAGE.DEFAULT;
                this.toggleState(
                    'sending',
                    false,
                    reason.MESSAGE || defaultMessage.MESSAGE,
                    reason.DETAILS || defaultMessage.DETAILS
                );
            });
    },

    getSendDataStrategy() {
        throw new Error(
            'The send data strategy getter is supposed to be supplied by a subclass.'
        );
    },

    getExportDataStrategy() {
        throw new Error(
            'The export data strategy getter is supposed to be supplied by a subclass.'
        );
    },

    trigger() {
        _super.prototype.trigger.apply(this, arguments);
    },
});
