define([
    "jquery",
    "underscore",
    "backbone",
    "bootstrap",
    'bootstrap_table',
    "bootstrapValidator",
    "contrib/text!app/templates/Modals/AddTask.html",
    'app/collections/Indexes',
    'app/views/DropdownList/List',
    'app/collections/Apps',
    'splunk.util'
], function(
    $,
    _,
    Backbone,
    Bootstrap,
    BootstrapTable,
    BootstrapValidator,
    AddTaskDialogTemplate,
    Indexes,
    DropdownList,
    Apps,
    splunkdUtils
){
    return Backbone.View.extend({
        template: _.template(AddTaskDialogTemplate),

        events: {
            "submit form": "addTask"
        },

        initialize: function(options) {
            this.indexes = new Indexes();
            this.listenToOnce(this.indexes, 'sync', this.initIndexList);
            this.indexDropdownList = new DropdownList({model: this.indexes, defaultValue: "default"});
            this.indexes.fetch();

            this.apps = new Apps();
            this.listenToOnce(this.apps, 'sync', this.initPage);
            this.appDropdownList = new DropdownList({model: this.apps, defaultValue: "Splunk_TA_f5-bigip"});
            this.apps.fetch();

        },

        initPage: function() {
            this.$("[name=new_task_dialog_appName]").html(this.appDropdownList.render().el);
        },


        initIndexList: function() {
            this.$("[name=new_task_dialog_index]").html(this.indexDropdownList.render().el);
        },


        render: function() {
            this.$el.html(this.template({}));

            var dlg=this;
            this.$("[role=dialog]").on('hidden.bs.modal', function() {
                dlg.undelegateEvents();
            });

            this.$("[role=dialog]").on('shown.bs.modal', function() {
                $("#Splunk_TA_f5-bigip_server_select_panel_table").bootstrapTable({
                    url: splunkdUtils.make_url('custom/Splunk_TA_f5-bigip/manage_servers/servers')
                });

                $("#Splunk_TA_f5-bigip_template_select_panel_table").bootstrapTable({
                    url: splunkdUtils.make_url('custom/Splunk_TA_f5-bigip/manage_templates/templates')
                });

            });

            var validated=this.$("input,select,textarea").not("[type='submit']");
            validated.jqBootstrapValidation("destroy");
            validated.filter( function () {
                    return true; //$(this).is(":visible");
                }).jqBootstrapValidation();

            return this;
        },

        getSelectionListSelections: function(id) {
            var ret = "";
            var selections = this.$(id).bootstrapTable('getSelections');

            for (var index=0; index < selections.length; ++index){
                if (ret == "")
                    ret += selections[index].id;
                else
                    ret += " | " + selections[index].id;
            }
            return ret;
        },

        addTask: function() {
            var new_task_val = {
                "appName" : this.appDropdownList.getSelection(),
                "name" : this.$("[name=new_task_dialog_name]").val(),
                "description" : this.$("[name=new_task_dialog_description]").val(),
                "interval" : this.$("[name=new_task_dialog_interval]").val(),
                "sourcetype" : this.$("[name=new_task_dialog_sourcetype]").val(),
                "index" : this.indexDropdownList.getSelection(),
                "disabled" : "0",
                "servers" : this.getSelectionListSelections("#Splunk_TA_f5-bigip_server_select_panel_table"),
                "templates" : this.getSelectionListSelections("#Splunk_TA_f5-bigip_template_select_panel_table")
            };

            var dlg=this;
            //this.model.create(new_task_val, {wait: true} );
            this.model.create(new_task_val, {wait: true, error: function(model,response){
                var rsp=response.responseText;
                var rspx=rsp.substring(rsp.indexOf('<body>'),rsp.length)
                    .replace(new RegExp('<(/?)(h1|p|html|body)([^>]*)>','g'),'<$1div$3>')
                    .replace(new RegExp('<[^>]*/>','g'),'');
                var splunk_error_page=$(rspx);
                var status=splunk_error_page.find('.status').text();
                var msg=splunk_error_page.find('.msg').text();
                alert(status+':\n'+msg);
            },success: function(){
                dlg.$("[role=dialog]").modal('hide');
                dlg.undelegateEvents();
            } } );
        },

        modal: function() {
            this.$("[role=dialog]").modal({backdrop: 'static', keyboard: false});
        }

    });

});

