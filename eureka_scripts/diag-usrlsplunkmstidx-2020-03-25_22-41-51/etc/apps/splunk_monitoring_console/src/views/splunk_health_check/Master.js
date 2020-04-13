define([
    'jquery',
    'underscore',
    'module',
    'backbone',
    'views/Base',
    'views/shared/controls/ControlGroup',
    'views/shared/controls/SyntheticSelectControl',
    'splunk_monitoring_console/views/utils',
    'splunk_monitoring_console/views/splunk_health_check/ProgressBar',
    'splunk_monitoring_console/views/splunk_health_check/Action',
    'splunk_monitoring_console/views/splunk_health_check/Filters',
    'splunk_monitoring_console/views/splunk_health_check/Tasks',
    'splunk_monitoring_console/views/splunk_health_check/Scope',
    'splunk_monitoring_console/views/splunk_health_check/Sidebar',
    'splunk_monitoring_console/views/splunk_health_check/InfoDialog',
    'contrib/text!splunk_monitoring_console/views/splunk_health_check/Master.html',
    'splunk_monitoring_console/views/splunk_health_check/Master.pcss',
    'uri/route',
    'splunk.util'
], function(
    $,
    _,
    module,
    Backbone,
    BaseView,
    ControlGroup,
    SyntheticSelectControl,
    utils,
    ProgressBarView,
    ActionView,
    FiltersView,
    TasksView,
    ScopeView,
    SidebarView,
    InfoDialog,
    Template,
    css,
    route,
    splunkUtils
) {
    return BaseView.extend({
        moduleId: module.id,
        template: Template,
        events: {
            'click a.expand-results': function(e) {
                var task = this.getTaskFromTarget(e);
                this.children.infoDialog = new InfoDialog({
                    model: {
                        task: task,
                        application: this.model.application
                    },
                    onHiddenRemove: true
                });
                
                this.children.infoDialog.render().appendTo($("body"));
                this.children.infoDialog.show();

                e.preventDefault();
            }
        },

        initialize: function() {
            BaseView.prototype.initialize.apply(this, arguments);

            this.collection.tasks.reset(this.collection.tasks.filter(function(task) {
                var environment = this.model.dmcConfigs.isDistributedMode() ? 'distributed' : 'standalone';
                var excludedEnvironments = (task.getEnvironmentsToExclude() || '').split(',');

                return !_.contains(excludedEnvironments, environment);
            }, this));

            this.children.scopeView = new ScopeView({
                model: {
                    conductor: this.model.conductor,
                    dmcConfigs: this.model.dmcConfigs
                },
                collection: {
                    tasks: this.collection.tasks,
                    appLocalsUnfilteredAll: this.collection.appLocalsUnfilteredAll
                }
            });

            this.children.progressView = new ProgressBarView({
                model: this.model.conductor
            });
            
            this.children.actionView = new ActionView({
                model: {
                    conductor: this.model.conductor
                }
            });

            this.children.filtersView = new FiltersView({
                collection: {
                    tasks: this.collection.tasks
                }
            });

            this.children.tasksView = new TasksView({
                model: {
                    conductor: this.model.conductor,
                    dmcConfigs: this.model.dmcConfigs
                },
                collection: {
                    tasks: this.collection.tasks
                }
            });

            this.children.sidebar = new SidebarView({
                model: {
                    task: undefined,
                    dmcConfigs: this.model.dmcConfigs,
                    application: this.model.application
                }
            });

            this.model.conductor.on('hideFilters', function() {
                this.children.filtersView.detach();
                if (this.model.dmcConfigs.isDistributedMode()) {
                    this.children.scopeView.enable();
                }
            }, this);

            this.model.conductor.on('showFilters', function() {
                this.$('.health-check-filters-container').append(this.children.filtersView.render().$el);
            }, this);

            this.children.filtersView.on('hideResultsSidebar', function() {
                this.updateSidebar();
            }, this);

            this.children.actionView.on('startCheck', function() {
                if (this.model.dmcConfigs.isDistributedMode()) {
                    this.children.scopeView.disable();
                }
            }, this);

            this.children.actionView.on('hideResultsSidebar', function() {
                this.updateSidebar();
            }, this);

            this.children.sidebar.on('hideResultsSidebar', function() {
                this.updateSidebar();
            }, this);

            this.collection.tasks.on('showResultSidebar', function(task) {
                this.updateSidebar(task);
            }, this);
        },

        updateScopeView: function() {
            if (this.model.conductor.getState() == 'stopped') {
                this.children.scopeView.enable();
            } else {
                this.children.scopeView.disable();
            }
        },

        updateSidebar: function(task) {
            if (task) {
                this.children.sidebar.setTask(task);
                this.$('.health-check-sidebar-display').append(this.children.sidebar.render().$el);
                this.$('.health-check-sidebar-display').css('display','');
                this.$('.splunk-health-check-container').css('padding-right', '500px');
            } else {
                this.$('.health-check-sidebar-display').hide();
                this.$('.splunk-health-check-container').css('padding-right', '0');
            }
        },

        getTaskFromTarget: function(event) {
            var id = $(event.target).closest('a').data('check-item-id');
            return _.find(this.collection.tasks.models, function(task) {
                return id === task.getID();
            }, this);
        },

        render: function() {
            var root = this.model.application.get('root');
            var locale = this.model.application.get('locale');
            var healthCheckContentLink = route.page(root, locale, 'splunk_monitoring_console', 'monitoringconsole_check_list');

            this.$el.html(this.compiledTemplate({
                splunkUtils: splunkUtils,
                healthCheckContentLink: healthCheckContentLink
            }));

            this.$('.health-check-scope').append(this.children.scopeView.render().$el);
            this.$('.progress-bar-module').append(this.children.progressView.render().$el);
            this.$('.action-module').append(this.children.actionView.render().$el);
            this.$('.health-check-table-display').append(this.children.tasksView.render().$el);
            this.$('.health-check-sidebar-display').append(this.children.sidebar.render().$el);

            this.updateSidebar();

            return this;
        }
    });
});