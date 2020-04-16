define([
    "jquery",
    "underscore",
    "backbone",
    "bootstrap",
    "bootstrapValidator",
    "contrib/text!app/templates/Modals/AddTemplate.html",
    'app/collections/Apps',
    'app/views/DropdownList/List'
], function(
    $,
    _,
    Backbone,
    Bootstrap,
    BootstrapValidator,
    AddTemplateDialogTemplate,
    Apps,
    DropdownList
){
    return Backbone.View.extend({
        template: _.template(AddTemplateDialogTemplate),

        events: {
            "submit form": "addTemplate"
        },

        initialize: function(options) {
            this.apps = new Apps();
            this.listenToOnce(this.apps, 'sync', this.initPage);
            this.appDropdownList = new DropdownList({model: this.apps, defaultValue: "Splunk_TA_f5-bigip"});
            this.apps.fetch();
        },

        initPage: function() {
            this.$("[name=new_template_dialog_app_name]").html(this.appDropdownList.render().el);
        },

        render: function() {
            this.$el.html(this.template({}));


            var dlg=this;
            this.$("[role=dialog]").on('hidden.bs.modal', function() {
                dlg.undelegateEvents();
            });

            var validated=this.$("input,select,textarea").not("[type='submit']");
            validated.jqBootstrapValidation("destroy");
            validated.filter( function () {
                    return $(this).is(":visible");
                }).jqBootstrapValidation();

            return this;
        },

        addTemplate: function() {
            var new_template_val = {
                "name" : this.$("[name=new_template_dialog_name]").val(),
                "description" : this.$("[name=new_template_dialog_description]").val(),
                "appName" : this.appDropdownList.getSelection(),
                "content" : this.$("[name=new_template_dialog_content]").val()
            };
            var dlg=this;
            // ignore any other request
            //this.model.create(new_template_val, {wait: true} );
            this.model.create(new_template_val, {wait: true, error: function(model,response){
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

