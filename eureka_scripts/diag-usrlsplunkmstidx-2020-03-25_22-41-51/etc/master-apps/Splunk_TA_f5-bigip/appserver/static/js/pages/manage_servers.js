require([
    'jquery',
    'underscore',
    'backbone',
    "bootstrap",
    "splunkjs/mvc/headerview",
    "splunk.util",
    'app/collections/Servers',
    'app/views/ServersTable/Table',
    'app/views/Modals/AddServer'
    ],
function(
    $,
    _,
    Backbone,
    Bootstrap,
    HeaderView,
    splunkdUtils,
    Servers,
    ServersTable,
    AddServerDialog
) {
    var headerView = new HeaderView({
        id: 'header',
        section: 'dashboards',
        el: $('.header'),
        acceleratedAppNav: true
    }).render();

    // show server list
    var servers = new Servers();
    var server_list = new ServersTable({model: servers, container: "#f5_bigip_server_list"});
    servers.fetch();

    // enable #addServerBtn until servers is ready?
    servers.on("sync", function() {
        $("#addServerBtn").removeAttr("disabled");
    });

    $("#addServerBtn").click(function() {
        var dlg = new AddServerDialog({
            el: $("#f5_bigip_server_add_dialog"),
            model: servers
        }).render();
        dlg.modal();
    });

});
