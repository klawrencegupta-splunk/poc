require([
    'jquery',
    'underscore',
    'backbone',
    "bootstrap",
    "splunkjs/mvc/headerview",
    "splunk.util",
    'app/collections/Tasks',
    'app/views/TasksTable/Table',
    'app/views/Modals/AddTask'
    ],
function(
    $,
    _,
    Backbone,
    Bootstrap,
    HeaderView,
    splunkdUtils,
    Tasks,
    TasksTable,
    AddTaskDialog
) {
    var headerView = new HeaderView({
        id: 'header',
        section: 'dashboards',
        el: $('.header'),
        acceleratedAppNav: true
    }).render();

    // show server list
    var templates = new Tasks();
    var template_list = new TasksTable({model: templates, container: "#f5_bigip_task_list"});
    templates.fetch();

    // enable #addServerBtn until servers is ready?
    templates.on("sync", function() {
        $("#addTaskBtn").removeAttr("disabled");
    });

    $("#addTaskBtn").click(function() {
        var dlg = new AddTaskDialog({
            el: $("#f5_bigip_task_add_dialog"),
            model: templates
        }).render();
        dlg.modal();
    });


});
