define([
    'underscore',
    'module',
    'backbone',
    'controllers/BaseManagerPageController',
    'splunk_monitoring_console/models/splunk_health_check/CheckList',
    'splunk_monitoring_console/collections/splunk_health_check/CheckLists',
    'splunk_monitoring_console/views/splunk_health_check_list/ActionCell',
    'splunk_monitoring_console/views/splunk_health_check_list/GridRow',
    'splunk_monitoring_console/views/splunk_health_check_list/AddEditDialog',
    'splunk_monitoring_console/views/splunk_health_check_list/PageController.pcss',
    'views/shared/pcss/basemanager.pcss'
], function(
    _,
    module,
    Backbone,
    BaseController,
    CheckListModel,
    CheckListsCollection,
    ActionCell,
    GridRow,
    AddEditDialog,
    css,
    cssShared
) {
    return BaseController.extend({
        moduleId: module.id,

        initialize: function(options) {
            options.entitiesPlural = _('Health Check Items').t();
            options.entitySingular = _('Health Check Item').t();
            // TODO: fill in page description and learMore link
            options.header = {
                pageDesc: _('').t(),
                learnMoreLink: ''
            };
            options.entitiesCollectionClass = CheckListsCollection;
            options.entityModelClass = CheckListModel;
            options.grid = {
                showAllApps: true,
                showOwnerFilter: false,
                showSharingColumn: false,
                showStatusColumn: false
            };
            options.customViews = options.customViews || {};
            options.customViews.ActionCell = ActionCell;
            options.customViews.GridRow = GridRow;
            options.customViews.AddEditDialog = AddEditDialog;

            BaseController.prototype.initialize.call(this, options);
        }
    });
});