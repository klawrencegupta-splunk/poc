const template = require('contrib/text!./InstrumentationLog.html');
const _ = require('underscore');
const $ = require('jquery');
const Component = require('splunk_instrumentation/Instrumentation/framework/Component');
const Model = require('splunk_instrumentation/Instrumentation/framework/Model');
const Collection = require('splunk_instrumentation/Instrumentation/framework/Collection');
const DateRangeSelector = require('splunk_instrumentation/Instrumentation/views/controls/DateRangeSelector');
const TimeRange = require('models/shared/TimeRange');
const constants = require('splunk_instrumentation/Instrumentation/constants');
const DataReportingLog = require('splunk_instrumentation/Instrumentation/models/DataReportingLog');
const Paginator = require('splunk_instrumentation/Instrumentation/views/controls/Paginator');
const SortingTableHeadCell = require('splunk_instrumentation/Instrumentation/views/controls/table/SortingTableHeadCell');
const SortingTableHeadCellGroup =
require('splunk_instrumentation/Instrumentation/views/controls/table/SortingTableHeadCellGroup');
const InstrumentationService = require('splunk_instrumentation/Instrumentation/services/InstrumentationService');
const time = require('splunk_instrumentation/Instrumentation/services/time');
const splunkd = require('splunk_instrumentation/Instrumentation/services/splunkd');

require('./InstrumentationLog.pcss');


const _super = Component;
module.exports = Component.extend({
    name: 'InstrumentationLog',

    template,

    components: {
        dateRangeSelector() {
            return new DateRangeSelector({ model: this.viewModel.get('timeRange') });
        },
        paginator() {
            return new Paginator({
                collection: this.collection,
                model: this.paginationModel,
            });
        },
        sortingTableHeadCell(id) {
            let label;
            let field;

            if (!this.tableHeadGroup) {
                this.tableHeadGroup = new SortingTableHeadCellGroup();
                this.listenTo(this.tableHeadGroup, 'sorted', this.onColumnSorted.bind(this));
            }

            switch (id) {
                case 'sendTime':
                    label = _('Date Sent').t();
                    field = '_time';
                    break;
                case 'status':
                    label = _('Status').t();
                    field = 'status';
                    break;
                case 'dateRange':
                    label = _('Date Range').t();
                    field = 'start';
                    break;
                default:
                    break;

            }

            const newComponent = new SortingTableHeadCell({
                model: new Model({
                    label,
                    field,
                }),
            });

            this.tableHeadGroup.add(id, newComponent);

            return newComponent;
        },
    },

    /**
     * Usage: `new InstrumentationLog({ dataType: DESIRED_DATA_TYPE })`
     *         where DESIRED_DATA_TYPE is one of the `constants.DATA_TYPES`.
     */
    initialize(opt, ...args) {
        this.options = opt || {};
        _super.prototype.initialize.apply(this, [opt, ...args]);

        this.instrumentationService = new InstrumentationService();

        if (!opt.messageService) {
            throw new Error('No MessageService provided');
        } else {
            this.messageService = opt.messageService;
        }

        this.dataType = this.options.dataType;

        this.searchKeepAliveInterval = setInterval(() => {
            if (!this.viewModel) return;

            const searchData = this.viewModel.get('searchData');
            if (searchData) {
                searchData.touch();
            }
        }, constants.SEARCH_KEEP_ALIVE_INTERVAL);
    },

    beforeFirstRender() {
        // All log models retrieved from the server
        this.collection = new Collection();
        this.collection.model = DataReportingLog;
        this.collection.paging = new Model({
            total: 0,
        });

        this.paginationModel = new Model({
            count: 10,
            offset: 0,
        });

        this.lastPageFetched = _.pick(this.paginationModel.attributes, 'offset', 'count');
        this.paginationModel.on('change', () => {
            const pendingPageFetch = _.pick(this.paginationModel.attributes, 'offset', 'count');
            if (pendingPageFetch.offset === this.lastPageFetched.offset &&
            pendingPageFetch.count === this.lastPageFetched.count) {
                // When the collection is fetched initially, the first page will be fetched as well.
                // No need to fetch the same content again in that case (or ever).
                return;
            }
            this.lastPageFetched = pendingPageFetch;

            this.viewModel.get('searchData').getResults(pendingPageFetch).then((outcome) => {
                this.collection.reset(outcome.results);
            })
            .fail(() => {
                // If we can no longer grab results for the current
                // search job, create a new one. (May happen if the
                // user's computer has been asleep for longer than
                // the timeout of the search job.)
                this.fetchLogs().fail(() => {
                    this.displayServerError();
                });
            });
        });

        const timeRange = new TimeRange({
            earliest: '-30d@d',
            latest: 'now',
        });

        timeRange.on('change', _.debounce(() => {
            this.fetchLogs();
            this.updateViewSelectedDataHref();
            this.paginationModel.set('offset', 0);
        }, 50));

        this.viewModel = new Model({
            timeRange,
            hasLoaded: false,
            searchData: undefined,
        });

        $.when(
            this.fetchLogs(),
            this.updateViewSelectedDataHref()
        ).then(() => {
            this.viewModel.set('hasLoaded', true);
        });
    },

    updateViewSelectedDataHref() {
        const timeRange = this.viewModel.get('timeRange');
        return time.parseSplunkTimeStrings(
            timeRange.get('earliest') || '0', timeRange.get('latest') || 'now'
        ).then((dates) => {
            dates[1] = time.nudgeMidnightToPreviousDay(dates[1]);
            this.viewModel.set('viewAllDataHref', this.getUrlFromTimePicker(
                dates[0], dates[1]
            ));
        });
    },

    onColumnSorted: _.debounce(function onColumnSorted(component) {
        this.paginationModel.set('offset', 0);

        const sortOrder = component.model.get('sortOrder');

        if (!sortOrder) {
            this.fetchLogs();
        } else {
            const sortSPL = ('| sort $dir$field'.replace('$dir', sortOrder === 'asc' ? '+' : '-')
            .replace('$field', component.model.get('field'))
            );

            this.fetchLogs({
                search: sortSPL,
            });
        }
    }),

    fetchLogs(resultOptions) {
        let getLogsStrategy;
        const timeRange = this.viewModel.get('timeRange');

        const earliest = timeRange.get('earliest');
        const latest = timeRange.get('latest');

        if (this.dataType === constants.DATA_TYPES.ANONYMOUS) {
            getLogsStrategy = this.instrumentationService.getAnonymousReportingLogs
            .bind(this.instrumentationService);
        } else if (this.dataType === constants.DATA_TYPES.LICENSE) {
            getLogsStrategy = this.instrumentationService.getLicenseReportingLogs
            .bind(this.instrumentationService);
        }

        const deferred = getLogsStrategy(
        earliest,
        latest,
        _.extend({}, _.pick(this.paginationModel.attributes, 'offset', 'count'), resultOptions)
        );

        return deferred.then(searchData => {
            this.collection.reset(searchData.outcome.results);
            this.collection.paging.set('total', searchData.job.entry[0].content.eventCount);
            this.viewModel.set('searchData', searchData);
            this.messageService.clear();
        }).fail(() => {
            this.displayServerError();
        });
    },

    /**
     * Wrapping getTelemetryDataUrl. Called from timerange picker.
     * Constructing startDate and endDate to feed into getTelemetryDataUrl.
     * We also nudge latest to 2 day in the future.
     * earliest: Date object
     * latest: Date object
     *
     */

    getUrlFromTimePicker(earliest, latest) {
        const startDate = time.toYearMonthDayString(earliest);
        const endDate = time.toYearMonthDayString(latest);

        latest.setDate(latest.getDate() + 2);

        return this.getTelemetryDataUrl(this.normalizeDate(earliest),
                                        this.normalizeDate(latest),
                                        startDate, endDate);
    },

    /**
     * Wrapping getTelemetryDataUrl. Called from logs data.
     * earliest: Date object
     * latest: Date object
     * startDate: String object or undefined
     * endDate: String object or undefined
     * If old data received, startDate and endDate will be undefined
     */

    getUrlFromLogs(earliest, latest, startDate, endDate) {
        return this.getTelemetryDataUrl(this.normalizeDate(earliest),
                                        this.normalizeDate(latest),
                                        startDate, endDate);
    },

    /**
     * Converting Date object to integer unix timestamp
     * date: Date object
     */
    normalizeDate(date) {
        if (date.constructor === Date) {
            return Math.floor(date.getTime() / 1000);
        } else if (_.isString(date) || _.isNumber(date)) {
            return parseInt(date, 10);
        } else {
            throw new Error('Unrecognized arguments');
        }
    },

    /**
      * Construct an URL encoded url to query the data.
      * earliest: Date object
      * latest: Date object
      * startDate: String or undefined
      * endDate: String or undefined
      */
    getTelemetryDataUrl(earliest, latest, startDate, endDate) {
        if (earliest < constants.EPOCH_DATE.getTime() / 1000) {
            earliest = 0;
        }

        /**
         * From this function scenario, there are two scenario.
         * 1. New log data with start_date and end_date, or from timerange picker:
         *  - Plug in the start and end from the log data as timerange picker parameter
         *  - Use start_date and end_date as an additional filter to the custom search query
         * 2. Old log data (old logic):
         *  - Plug in start and end from log data as timerange picker parameter.
         */

        let searchURL = constants.SEARCH_PAGE_URL;
        searchURL += '?q=';
        if (this.dataType === constants.DATA_TYPES.ANONYMOUS) {
            searchURL += encodeURIComponent(constants.ANONYMIZED_TELEMETRY_EVENTS_BY_TIME_QUERY);
        } else {
            searchURL += encodeURIComponent(constants.LICENSE_TELEMETRY_EVENTS_QUERY);
        }

        if (startDate && endDate) {
            const dateSearch = ` | spath date | search date >="${startDate}" date <="${endDate}" `;
            searchURL += encodeURIComponent(dateSearch);
        }

        if (this.dataType === constants.DATA_TYPES.ANONYMOUS) {
            searchURL += `&earliest=${earliest}`;
            searchURL += `&latest=${latest}`;
        } else {
            const splitStartDate = startDate.split('-');
            const splitEndDate = endDate.split('-');
            const newEarliest = new Date(splitStartDate[0],
                parseInt(splitStartDate[1], 10) - 1, splitStartDate[2]);
            newEarliest.setDate(newEarliest.getDate() - 1);
            const newLatest = new Date(splitEndDate[0],
                parseInt(splitEndDate[1], 10) - 1, splitEndDate[2]);
            newLatest.setDate(newLatest.getDate() + 2);

            searchURL += `&earliest=${this.normalizeDate(newEarliest)}`;
            searchURL += `&latest=${this.normalizeDate(newLatest)}`;
        }

        return splunkd.routes.encodeRoot(searchURL);
    },

    displayServerError(exception, message) {
        this.messageService.error(message || constants.DEFAULT_SERVER_ERROR, exception);
    },

    remove(...arg) {
        if (this.searchKeepAliveInterval) {
            clearInterval(this.searchKeepAliveInterval);
        }
        return _super.prototype.remove.apply(this, arg);
    },
});
