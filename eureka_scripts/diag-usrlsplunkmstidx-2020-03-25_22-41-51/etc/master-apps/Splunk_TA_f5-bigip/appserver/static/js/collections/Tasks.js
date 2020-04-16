define([
    'jquery',
    'underscore',
    'backbone',
    'splunk.util',
    'app/models/Task'],
function(
    $,
    _,
    Backbone,
    splunkdUtils,
    Task
) {
    return Backbone.Collection.extend({
        url: splunkdUtils.make_url('custom/Splunk_TA_f5-bigip/manage_tasks/tasks'),
        model: Task
    });
});
