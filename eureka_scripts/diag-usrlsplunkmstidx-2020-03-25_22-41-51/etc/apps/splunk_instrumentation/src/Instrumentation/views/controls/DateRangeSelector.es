require('./DateRangeSelector.pcss');
const _ = require('underscore');
const $ = require('jquery');
const Model = require('splunk_instrumentation/Instrumentation/framework/Model');
const Component = require('splunk_instrumentation/Instrumentation/framework/Component');
const PopTart = require('views/shared/PopTart');
const TimeRangePickerDialog = require('views/shared/timerangepicker/dialog/Master');
const Times = require('collections/services/data/ui/Times');

/**
 * Usage:
 *
 * ```JavaScript
 * var timeRange = new TimeRange();
 * var selector = new DateRangeSelector({model: timeRange}).render();
 * selector.appendTo($yourNewHome);
 * ```
 */
const _super = Component;
const DateRangeSelector = _super.extend({
    name: 'DateRangeSelector',

    moduleId: module.id,

    className: 'date-range-selector',

    template: `
        <button class="btn toggle-button date-range-dropdown-button">
        <span class="pull-left"><%= viewModel.get("label") %></span>
        <span class="<%= getCaretClass %> pull-right"></span>
        </button>
    `,

    templateContext() {
        return {
            model: this.model,
            viewModel: this.viewModel,
            getCaretClass: this.getCaretClass(),
        };
    },

    events: {
        'click .toggle-button': 'toggle',
    },

    initialize() {
        this.viewModel = new Model();
        if (this.options.isPopup === undefined) {
            this.options.isPopup = true;
        }

        Component.prototype.initialize.apply(this, arguments);
        this.deferred = DateRangeSelector.fetchTimes()
            .then(this.setupPopTart.bind(this))
            .fail((reason) => {
                // TODO: Display error in modal
                console.error(reason);
            });
    },

    setupPopTart() {
        this.viewModel.set('label', _(this.model.generateLabel(DateRangeSelector.times)).t());

        this.dateRangePopTart = new PopTart({
            ignoreToggleMouseDown: true,
            ignoreClasses: ['ui-datepicker'],
        }).render();

        this.model.on('change', () => {
            this.dateRangePopTart.hide();
            this.viewModel.set('label', _(this.model.generateLabel(DateRangeSelector.times)).t());
        });

        if (this.isPopup()) {
            this.dateRangePopTart.$('.popdown-dialog-body')
                .removeClass('popdown-dialog-padded')
                .append(
                    this.createTimeRangeDialog().render().$el
                );
            $(document.body).append(this.dateRangePopTart.$el);
        } else {
            this.createTimeRangeDialog();
        }
    },

    createTimeRangeDialog() {
        this.timeRangePicker = new TimeRangePickerDialog({
            model: {
                timeRange: this.model,
                application: new Model(),
            },
            collection: DateRangeSelector.times,
            showPresets: true,
            // I guess we just have to re-opt-out every time
            // a new section is added to the core time picker dialog
            // that we don't want to show up...?
            showCustomRelative: false,
            showCustomRealTime: false,
            showCustomDateTime: false,
            showCustomAdvanced: false,
            // The pop-tarts within this pop-tart must be children
            // of this pop-tart, in the DOM sense, or else the parent
            // pop-tart will close itself when the children are clicked.
            // This option tells the date range dialog element to append
            // the child tarts to the parent tart instead of document.body.
            appendSelectDropdownsTo: this.isPopup() ? this.dateRangePopTart.$el : '.modal:visible',
        });
        return this.timeRangePicker;
    },

    getCaretClass() {
        return this.isPopup() ? 'caret' : 'icon-triangle-right-small';
    },

    isPopup() {
        return this.options.isPopup;
    },

    toggle() {
        if (this.isPopup()) {
            if (!this.dateRangePopTart.shown) {
                this.dateRangePopTart.show(this.$('.toggle-button'));
            } else {
                this.dateRangePopTart.hide();
            }
        }
    },

    remove() {
        if (this.dateRangePopTart) {
            this.dateRangePopTart.remove();
            this.dateRangePopTart = null;
        }
        return _super.prototype.remove.apply(this, arguments);
    },
}, {
    fetchTimes() {
        if (!DateRangeSelector.times) {
            DateRangeSelector.times = new Times();
            return DateRangeSelector.times.fetch().then(() => {
                DateRangeSelector.times.reset(DateRangeSelector.times.reject((m) => {
                    if (m.isRealTime()) {
                        return true;
                    }
                    // Reject all "last ..." entries that aren't counting in days.
                    if (m.isLast() && !m.entry.content.get('earliest_time').match(/-\d+d/)) {
                        return true;
                    }
                    return false;
                }));
            });
        }
        const deferred = new $.Deferred();
        deferred.resolve();
        return deferred;
    },
});

module.exports = DateRangeSelector;
