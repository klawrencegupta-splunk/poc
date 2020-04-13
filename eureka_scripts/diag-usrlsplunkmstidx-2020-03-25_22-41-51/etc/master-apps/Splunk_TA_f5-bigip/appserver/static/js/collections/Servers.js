define([
    'jquery',
    'underscore',
    'backbone',
    'splunk.util',
    'app/models/Server'],
function(
    $,
    _,
    Backbone,
    splunkdUtils,
    Server
) {
    return Backbone.Collection.extend({
        url: splunkdUtils.make_url('custom/Splunk_TA_f5-bigip/manage_servers/servers'),
        model: Server
    });
});
