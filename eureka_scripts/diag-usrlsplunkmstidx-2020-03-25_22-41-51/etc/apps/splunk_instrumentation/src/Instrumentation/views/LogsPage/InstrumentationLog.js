var style = require('./InstrumentationLog.pcss'),
    template = require('contrib/text!./InstrumentationLog.html'),
    _ = require('underscore'),
    $ = require('jquery'),
    Backbone = require('backbone'),
    Component = require('Instrumentation/framework/Component'),
    Model = require('Instrumentation/framework/Model'),
    Collection = require('Instrumentation/framework/Collection'),
    DateRangeSelector = require('Instrumentation/views/controls/DateRangeSelector'),
    TimeRange = require('models/shared/TimeRange'),
    constants = require('Instrumentation/constants'),
    DataReportingLog = require('Instrumentation/models/DataReportingLog'),
    Paginator = require('Instrumentation/views/controls/Paginator'),
    SortingTableHeadCell = require('Instrumentation/views/controls/table/SortingTableHeadCell'),
    SortingTableHeadCellGroup = require('Instrumentation/views/controls/table/SortingTableHeadCellGroup'),
    InstrumentationService = require('Instrumentation/services/InstrumentationService'),
    time = require('Instrumentation/services/time');

var _super = Component;
module.exports = Component.extend({
    name: 'InstrumentationLog',

    template: template,

    components: {
        dateRangeSelector: function () {
            return new DateRangeSelector({ model: this.viewModel.get('timeRange') });
        },
        paginator: function () {
            return new Paginator({
                collection: this.collection,
                model: this.paginationModel
            });
        },
        sortingTableHeadCell: function (id) {
            var label,
                field;
            
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
                    field = 'start'
                    break;
            }
            
            var newComponent = new SortingTableHeadCell({
                model: new Model({
                    label: label,
                    field: field
                })
            });
            
            this.tableHeadGroup.add(id, newComponent);
            
            return newComponent;
        }
    },

    /**
     * Usage: `new InstrumentationLog({ dataType: DESIRED_DATA_TYPE })`
     *         where DESIRED_DATA_TYPE is one of the `constants.DATA_TYPES`.
     */
    initialize: function (opt) {
        this.options = opt || {};
        _super.prototype.initialize.apply(this, arguments);

        this.instrumentationService = new InstrumentationService();

        if (!opt.messageService) {
            throw new Error("No MessageService provided");
        } else {
            this.messageService = opt.messageService;
        }

        this.dataType = this.options.dataType;
        
        this.searchKeepAliveInterval = setInterval(function () {
            if (!this.viewModel) return;
            
            var searchData = this.viewModel.get('searchData');
            if (searchData) {
                searchData.touch();
            }
        }.bind(this), constants.SEARCH_KEEP_ALIVE_INTERVAL);
    },

    beforeFirstRender: function () {
        // All log models retrieved from the server
        this.collection = new Collection();
        this.collection.model = DataReportingLog;
        this.collection.paging = new Model({
            total: 0
        });

        this.paginationModel = new Model({
            count: 10,
            offset: 0
        });

        this.lastPageFetched = _.pick(this.paginationModel.attributes, 'offset', 'count');
        this.paginationModel.on('change', function () {
            var pendingPageFetch = _.pick(this.paginationModel.attributes, 'offset', 'count');
            if (pendingPageFetch.offset == this.lastPageFetched.offset &&
                    pendingPageFetch.count == this.lastPageFetched.count) {
                // When the collection is fetched initially, the first page will be fetched as well.
                // No need to fetch the same content again in that case (or ever).
                return;
            }
            this.lastPageFetched = pendingPageFetch;

            this.viewModel.get('searchData').getResults(pendingPageFetch).then(function (outcome) {
                this.collection.reset(outcome.results);
            }.bind(this)).
            fail(function () {
                // If we can no longer grab results for the current
                // search job, create a new one. (May happen if the
                // user's computer has been asleep for longer than
                // the timeout of the search job.)
                this.fetchLogs().fail(function () {
                    this.displayServerError();
                }.bind(this));
            }.bind(this));
        }.bind(this));

        var timeRange = new TimeRange({
            earliest : '-30d@d',
            latest : 'now'
        });

        timeRange.on('change', _.debounce(function () {
            this.fetchLogs();
            this.updateViewSelectedDataHref();
            this.paginationModel.set('offset', 0);
        }.bind(this), 50));

        this.viewModel = new Model({
            timeRange: timeRange,
            hasLoaded: false,
            searchData: undefined
        });

        $.when(
            this.fetchLogs(),
            this.updateViewSelectedDataHref()
        ).then(function () {
            this.viewModel.set('hasLoaded', true);
        }.bind(this));
    },
    
    updateViewSelectedDataHref: function () {
        var timeRange = this.viewModel.get('timeRange');
        
        return time.parseSplunkTimeStrings(timeRange.get('earliest') || "0", timeRange.get('latest') || "now").
            then(function (dates) {
                time.nudgeMidnightToPreviousDay(dates[1]);
                this.viewModel.set('viewAllDataHref', this.getTelemetryDataUrl(
                    dates[0], dates[1]
                ));
            }.bind(this));
    },
    
    onColumnSorted: _.debounce(function (component) {
        this.paginationModel.set('offset', 0);
        
        var sortOrder = component.model.get('sortOrder');
        
        if (!sortOrder) {
            this.fetchLogs();
        } else {
            var sortSPL = ('| sort $dir$field'.
                replace('$dir', sortOrder == 'asc' ? '+' : '-').
                replace('$field', component.model.get('field'))
            );
            
            this.fetchLogs({
                search: sortSPL
            });
        }
    }),

    fetchLogs: function (resultOptions) {
        var deferred,
            earliest,
            latest,
            getLogsStrategy,
            timeRange = this.viewModel.get('timeRange');

        earliest = timeRange.get('earliest');
        latest = timeRange.get('latest');
        
        if (this.dataType === constants.DATA_TYPES.ANONYMOUS) {
            getLogsStrategy = this.instrumentationService.
                getAnonymousReportingLogs.
                bind(this.instrumentationService);
        } else if (this.dataType === constants.DATA_TYPES.LICENSE) {
            getLogsStrategy = this.instrumentationService.
                getLicenseReportingLogs.
                bind(this.instrumentationService);
        }
        
        deferred = getLogsStrategy(
            earliest,
            latest,
            _.extend({}, _.pick(this.paginationModel.attributes, 'offset', 'count'), resultOptions)
        );

        return deferred.then(function (searchData) {
            this.collection.reset(searchData.outcome.results);
            this.collection.paging.set('total', searchData.job.entry[0].content.eventCount);
            this.viewModel.set('searchData', searchData);
            this.messageService.clear();
        }.bind(this)).fail(function () {
            this.displayServerError();
        }.bind(this));
    },

    getLogsUrl: function () {
        if (this.dataType === constants.DATA_TYPES.ANONYMOUS) {
            return constants.INSTRUMENTATION_CONTROLLER_URL + '/anonymous_data_logs';
        } else if (this.dataType === constants.DATA_TYPES.LICENSE) {
            return constants.INSTRUMENTATION_CONTROLLER_URL + '/license_data_logs';
        } else {
            throw new Error("Unrecognized dataType: " + this.dataType);
        }
    },

    /**
     * Accepts unix timestamps (as strings or numbers) or Date objects
     */
    getTelemetryDataUrl: function (earliest, latest) {
        var searchURL = constants.SEARCH_PAGE_URL;
                
        // Normalize parameters (ensure they're unix timestamps)
        if ((earliest.constructor === Date && latest.constructor === Date)) {
            earliest = Math.floor(earliest.getTime() / 1000);
            latest = Math.floor(latest.getTime() / 1000);
        } else if (!_([earliest, latest]).every(function (e) { return _.isString(e) || _.isNumber(e); })) {
            throw new Error("Unrecognized arguments: ", arguments);
        }

        if (parseInt(earliest, 10) < constants.EPOCH_DATE.getTime() / 1000) earliest = 0;
        
        if (this.dataType == constants.DATA_TYPES.ANONYMOUS) {
            searchURL += '?q=' + encodeURIComponent(constants.ANONYMIZED_TELEMETRY_EVENTS_BY_TIME_QUERY);
        } else {
            searchURL += '?q=' + encodeURIComponent(constants.LICENSE_TELEMETRY_EVENTS_QUERY);
        }
        
        searchURL += '&earliest=' + earliest;
        searchURL += '&latest=' + latest;
        
        return searchURL;
    },

    displayServerError: function (exception, message) {
        message = message || constants.DEFAULT_SERVER_ERROR;
        this.messageService.error(message, exception);
    },
    
    remove: function () {
        if (this.searchKeepAliveInterval) {
            clearInterval(this.searchKeepAliveInterval);
        }
        return _super.prototype.remove.apply(this, arguments);
    }
});
