define([
    "jquery",
    "underscore",
    "backbone",
    "bootstrap",
    'bootstrap_table',
    "bootstrapValidator",
    "contrib/text!app/templates/Modals/EditTask.html",
    'app/collections/Indexes',
    'app/views/DropdownList/List',
    'splunk.util'
], function(
    $,
    _,
    Backbone,
    Bootstrap,
    BootstrapTable,
    BootstrapValidator,
    EditTaskDialogTemplate,
    Indexes,
    DropdownList,
    splunkdUtils
){
    return Backbone.View.extend({
        template: _.template(EditTaskDialogTemplate),

        events: {
            "submit form": "editTask"
        },

        initialize: function(options) {
            this.indexes = new Indexes();
            this.listenToOnce(this.indexes, 'sync', this.initIndexList);
            this.indexDropdownList = new DropdownList({model: this.indexes});
            this.indexes.fetch();
        },

        initIndexList: function() {
            this.$("[name=edit_task_dialog_index]").html(this.indexDropdownList.render().el);
        },

        render: function() {
            this.$el.html(this.template(this.model.toJSON()));
            var indexList = this.indexDropdownList;
            var index = this.model.get("index");

            this.$("[role=dialog]").on('shown.bs.modal', function() {
                $("#f5_bigip_edit_task_dialog_server_select_panel_table").bootstrapTable({
                    url: splunkdUtils.make_url('custom/Splunk_TA_f5-bigip/manage_servers/servers')
                });

                $("#f5_bigip_edit_task_dialog_template_select_panel_table").bootstrapTable({
                    url: splunkdUtils.make_url('custom/Splunk_TA_f5-bigip/manage_templates/templates')
                });

                // set index
                indexList.select(index);
            });

            this.initServerSelectionsUtil("servers", "#f5_bigip_edit_task_dialog_server_select_panel_table");
            this.initServerSelectionsUtil("templates", "#f5_bigip_edit_task_dialog_template_select_panel_table");

            var validated=this.$("input,select,textarea").not("[type='submit']");
            validated.jqBootstrapValidation("destroy");
            validated.filter( function () {
                    return true; // $(this).is(":visible");
                }).jqBootstrapValidation();


            var dlg=this;
            this.$("[role=dialog]").on('hidden.bs.modal', function() {
                dlg.undelegateEvents();
            });

            return this;
        },

        initServerSelectionsUtil: function(modelPropName, id) {
            // servers and templates need call to set default values
            var items = this.model.get(modelPropName).split("|");
            var nameAppDict = {};
            var itemName = "";
            var appName = "";
            for (var i = 0; i < items.length; i++) {
                try {
                    itemName = items[i].trim().split(":")[1].trim();
                    appName = items[i].trim().split(":")[0].trim();
                    if (itemName in nameAppDict)
                        nameAppDict[itemName][appName] = true;
                    else {
                        nameAppDict[itemName] = {};
                        nameAppDict[itemName][appName] = true;
                    }
                } catch (err) {
                    console.warn("get error when loading update dialog for task" + err);
                }
            }

            var selectbyAppName = this.selectItemsByAppName;
            this.$(id).on('load-success.bs.table', function () {
                selectbyAppName(id, nameAppDict);
            });
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


        selectItemsByAppName: function(id, nameAppDict) {
            var rows = this.$(id).bootstrapTable('getData');
            for (var i = 0; i < rows.length; ++i) {
                if (rows[i].name in nameAppDict)
                {
                    if (rows[i].appName == undefined)
                        rows[i].appName = "Splunk_TA_f5-bigip";

                    if (rows[i].appName in nameAppDict[rows[i].name])
                        rows[i]._selected = true;

                    this.$(id).bootstrapTable("updateRow", {index: i, row: rows[i]} );
                }
            }
        },

        editTask: function() {
            if (this.model.get("id") != this.$("[name=edit_task_dialog_id]").val())
                return;


            var edit_task_val = {
                "appName" : this.$("[name=edit_task_dialog_appName]").val(),
                "name" : this.$("[name=edit_task_dialog_name]").val(),
                "description" : this.$("[name=edit_task_dialog_description]").val(),
                "interval" : this.$("[name=edit_task_dialog_interval]").val(),
                "sourcetype" : this.$("[name=edit_task_dialog_sourcetype]").val(),
                "index" : this.indexDropdownList.getSelection(),
                "servers" : this.getSelectionListSelections("#f5_bigip_edit_task_dialog_server_select_panel_table"),
                "templates" : this.getSelectionListSelections("#f5_bigip_edit_task_dialog_template_select_panel_table")
             };

            var dlg=this;
            this.model.save(edit_task_val, {wait: true, error: function(model,response){
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

