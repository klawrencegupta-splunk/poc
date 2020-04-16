define([
    "jquery",
    "underscore",
    "backbone",
    "bootstrap",
    "bootstrapValidator",
    "contrib/text!app/templates/Modals/AddServer.html",
    'app/collections/Apps',
    'app/views/DropdownList/List'
], function(
    $,
    _,
    Backbone,
    Bootstrap,
    BootstrapValidator,
    AddServerDialogTemplate,
    Apps,
    DropdownList
){
    return Backbone.View.extend({
        template: _.template(AddServerDialogTemplate),

        events: {
            "submit form": "addServer",
            "change input[name=new_server_dialog_account_name]": "refreshCustomValidation",
            "change input[name=new_server_dialog_account_password]": "refreshCustomValidation"
        },

        initialize: function(options) {
            this.apps = new Apps();
            this.listenToOnce(this.apps, 'sync', this.initPage);
            this.appDropdownList = new DropdownList({model: this.apps, defaultValue: "Splunk_TA_f5-bigip"});
            this.apps.fetch();
        },

        initPage: function() {
            this.$("[name=new_server_dialog_appName]").html(this.appDropdownList.render().el);
        },

        render: function() {
            this.$el.html(this.template({}));
            this.refreshCustomValidation();

            var dlg=this;
            this.$("[role=dialog]").on('hidden.bs.modal', function() {
                dlg.undelegateEvents();
            });

            return this;
        },

        addServer: function() {

            var new_server_val = this.getInputs();

            var dlg=this;
            // ignore any other request
            //this.model.create(new_server_val, {wait: true} );
            this.model.create(new_server_val, {wait: true, error: function(model,response){
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
        },

        refreshCustomValidation: function() {
            var validated=this.$("input,select,textarea").not("[type='submit']");
            validated.jqBootstrapValidation("destroy");
            validated.removeData();

            validated.filter( function () {
                    return $(this).is(":visible");
                }).jqBootstrapValidation();
        },

        // not empty string
        NES: function(obj) {
            return obj != null && obj != "";
        },
        // is empty string
        IES: function(obj) {
            return obj == null || obj == "";
        },

        getInputs: function() {
            var val = {
                "appName" : this.appDropdownList.getSelection(),
                "name" : this.$("[name=new_server_dialog_name]").val(),
                "description" : this.$("[name=new_server_dialog_description]").val(),
                "interval" : this.$("[name=new_server_dialog_interval]").val(),
                "account_name" : "",
                "account_password" : "",
                "f5_bigip_url" : this.$("[name=new_server_dialog_url]").val(),
                "f5_bigip_partitions" : this.$("[name=new_server_dialog_partitions]").val()
            };

            val["account_name"] = this.$("[name=new_server_dialog_account_name]").val();
            if (this.NES(val["account_name"]))
                val["account_password"] = this.$("[name=new_server_dialog_account_password]").val();

            return val;
        }
    });

});
