define([
    'jquery',
    'underscore',
    'backbone',
    'splunk.util',
    'app/models/Index'],
function(
    $,
    _,
    Backbone,
    splunkdUtils,
    Index
) {
    return Backbone.Collection.extend({
        url: splunkdUtils.make_url('custom/Splunk_TA_f5-bigip/manage_apps/apps'),
        model: Index
    });
});
