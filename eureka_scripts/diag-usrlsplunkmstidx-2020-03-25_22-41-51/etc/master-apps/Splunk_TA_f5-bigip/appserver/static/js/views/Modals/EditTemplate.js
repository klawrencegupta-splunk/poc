define([
    "jquery",
    "underscore",
    "backbone",
    "bootstrap",
    "bootstrapValidator",
    "contrib/text!app/templates/Modals/EditTemplate.html"
], function(
    $,
    _,
    Backbone,
    Bootstrap,
    BootstrapValidator,
    EditTemplateDialogTemplate
){
    return Backbone.View.extend({
        template: _.template(EditTemplateDialogTemplate),

        events: {
            "submit form": "editTemplate"
        },

        render: function() {
            this.$el.html(this.template(this.model.toJSON()));

            var validated=this.$("input,select,textarea").not("[type='submit']");
            validated.jqBootstrapValidation("destroy");
            validated.filter( function () {
                    return $(this).is(":visible");
                }).jqBootstrapValidation();


            var dlg=this;
            this.$("[role=dialog]").on('hidden.bs.modal', function() {
                dlg.undelegateEvents();
            });

            return this;
        },

        editTemplate: function() {
            if (this.model.get("id") != this.$("[name=edit_template_dialog_id]").val())
                return;


            var edit_template_val = {
                "name" : this.$("[name=edit_template_dialog_name]").val(),
                "description" : this.$("[name=edit_template_dialog_description]").val(),
                "appName" : this.$("[name=edit_template_dialog_app_name]").val(),
                "content" : this.$("[name=edit_template_dialog_content]").val()
            };

            var dlg=this;
            this.model.save(edit_template_val, {wait: true, error: function(model,response){
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

