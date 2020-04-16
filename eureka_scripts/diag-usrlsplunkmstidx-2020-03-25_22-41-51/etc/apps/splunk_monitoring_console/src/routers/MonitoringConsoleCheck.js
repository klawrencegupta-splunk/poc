define(
    [
        'jquery',
        'underscore',
        'backbone',
        'routers/Base',
        'splunk_monitoring_console/models/splunk_health_check/Conductor',
        'splunk_monitoring_console/models/splunk_health_check/DmcConfigs',
        'splunk_monitoring_console/collections/splunk_health_check/Tasks',
        'splunk_monitoring_console/views/splunk_health_check/Master'
    ],
    function(
        $,
        _,
        Backbone,
        BaseRouter,
        ConductorModel,
        DmcConfigsModel,
        TasksCollection,
        MasterView
    ) {
        return BaseRouter.extend({
            initialize: function() {
                BaseRouter.prototype.initialize.apply(this, arguments);
                this.setPageTitle(_('Health Check').t());
                this.loadingMessage = _('Loading...').t();

                this.fetchAppLocals = true;

                this.collection.tasks = new TasksCollection();

                this.model.dmcConfigs = new DmcConfigsModel({}, {
                    appLocal: this.model.appLocal,
                    serverInfo: this.model.serverInfo
                });

                // conductor serves as a central controller that tracks all kinds of states, also handles all kinds of
                // user actions.
                // conductor needs to know the tasks and dmcConfigs
                this.model.conductor = new ConductorModel({}, {
                    tasks: this.collection.tasks,
                    dmcConfigs: this.model.dmcConfigs
                });
            },
            
            page: function(locale, app, page) {
                BaseRouter.prototype.page.apply(this, arguments);
                $.when(
                    this.collection.tasks.fetch({
                        // cannot move these to the collections default fetch option because that will break the
                        // sorting and pagination of the listing page
                        sort_key: 'category',
                        count: -1
                    }), 
                    this.model.dmcConfigs.fetch(),
                    this.deferreds.pageViewRendered
                ).done(function(){
                    if (this.shouldRender) {
                        $('.preload').replaceWith(this.pageView.el);

                        this.masterView = new MasterView({
                            model: {
                                application: this.model.application,
                                conductor: this.model.conductor,
                                dmcConfigs: this.model.dmcConfigs
                            },
                            collection: {
                                tasks: this.collection.tasks,
                                appLocals: this.collection.appLocals,
                                appLocalsUnfilteredAll: this.collection.appLocalsUnfilteredAll
                            }
                        });
                        $('.main-section-body').html(this.masterView.render().$el);
                    }
                }.bind(this));
            }
        });
    }
);