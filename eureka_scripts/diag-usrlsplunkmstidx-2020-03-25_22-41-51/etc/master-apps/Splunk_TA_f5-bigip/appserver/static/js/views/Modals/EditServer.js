define([
    "jquery",
    "underscore",
    "backbone",
    "bootstrap",
    "bootstrapValidator",
    "contrib/text!app/templates/Modals/EditServer.html"
], function(
    $,
    _,
    Backbone,
    Bootstrap,
    BootstrapValidator,
    EditServerDialogTemplate
){
    return Backbone.View.extend({
        template: _.template(EditServerDialogTemplate),

        events: {
            "submit form": "editServer",
            "change input[name=edit_server_dialog_account_name]": "refreshCustomValidation",
            "change input[name=edit_server_dialog_account_password]": "refreshCustomValidation"
        },

        // not empty string
        NES: function(obj) {
            return obj != null && obj != "";
        },

        // is empty string
        IES: function(obj) {
            return obj == null || obj == "";
        },

        render: function() {
            var json = this.resetRenderJson();
            this.$el.html(this.template(json));
            this.refreshCustomValidation();

            // var dlg = this;
            // var NES = this.NES;
            // this.$("[role=dialog]").on('shown.bs.modal', function() {
            //     if (NES(json.account_name))
            //         dlg.$("[name=edit_server_dialog_account_name]").val(json.account_name).change();
            //     if (NES(json.account_password))
            //         dlg.$("[name=edit_server_dialog_account_password]").val(json.account_password).change();
            // });
            //
            // this.$("[role=dialog]").on('hidden.bs.modal', function() {
            //     dlg.undelegateEvents();
            // });

            return this;
        },

        editServer: function() {
            if (this.model.get("id") != this.$("[name=edit_server_dialog_id]").val())
                return;


            var new_server_val = this.getInputs();

            var dlg=this;
            this.model.save(new_server_val, {wait: true, error: function(model,response){
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

        resetRenderJson: function() {
            var json = this.model.toJSON();
            return json;
        },

        refreshCustomValidation: function() {
            var validated=this.$("input,select,textarea").not("[type='submit']");
            validated.jqBootstrapValidation("destroy");
            validated.removeData();

            validated.filter( function () {
                    return $(this).is(":visible");
                }).jqBootstrapValidation();
        },

        getInputs: function() {
            var val = {
                "appName" : this.$("[name=edit_server_dialog_appName]").val(),
                "name" : this.$("[name=edit_server_dialog_name]").val(),
                "description" : this.$("[name=edit_server_dialog_description]").val(),
                "interval" : this.$("[name=edit_server_dialog_interval]").val(),
                "account_name" : "",
                "account_password" : "",
                "f5_bigip_url" : this.$("[name=edit_server_dialog_url]").val(),
                "f5_bigip_partitions" : this.$("[name=edit_server_dialog_partitions]").val()
            };

            val["account_name"] = this.$("[name=edit_server_dialog_account_name]").val();
            if (this.NES(val["account_name"])){
                val["account_password"] = this.$("[name=edit_server_dialog_account_password]").val();
            }
            return val;
        }


    });

});
