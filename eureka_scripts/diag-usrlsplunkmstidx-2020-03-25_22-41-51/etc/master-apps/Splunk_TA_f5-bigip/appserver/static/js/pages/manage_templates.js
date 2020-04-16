require([
    'jquery',
    'underscore',
    'backbone',
    "bootstrap",
    "splunkjs/mvc/headerview",
    "splunk.util",
    'app/collections/Templates',
    'app/views/TemplatesTable/Table',
    'app/views/Modals/AddTemplate'
    ],
function(
    $,
    _,
    Backbone,
    Bootstrap,
    HeaderView,
    splunkdUtils,
    Templates,
    TemplatesTable,
    AddTemplateDialog
) {
    var headerView = new HeaderView({
        id: 'header',
        section: 'dashboards',
        el: $('.header'),
        acceleratedAppNav: true
    }).render();

    // show server list
    var templates = new Templates();
    var template_list = new TemplatesTable({model: templates, container: "#f5_bigip_template_list"});
    templates.fetch();

    // enable #addServerBtn until servers is ready?
    templates.on("sync", function() {
        $("#addTemplateBtn").removeAttr("disabled");
    });

    $("#addTemplateBtn").click(function() {
        var dlg = new AddTemplateDialog({
            el: $("#f5_bigip_template_add_dialog"),
            model: templates
        }).render();
        dlg.modal();
    });


});


