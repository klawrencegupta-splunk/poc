define([
    "jquery",
    "underscore",
    "backbone",
    "bootstrap",
    "contrib/text!app/templates/TemplatesTable/Row.html",
    'app/views/Modals/EditTemplate'
], function(
    $,
    _,
    Backbone,
    Bootstrap,
    TemplatesTableRowTemplate,
    EditTemplateDialog
){
    return Backbone.View.extend({
        tagName: "tr",
        template: _.template(TemplatesTableRowTemplate),

        events: {
            "click a.update-item": "editTemplate",
            "click a.delete-item": "deleteTemplate"
        },

        initialize: function (options) {
            Backbone.View.prototype.initialize.call(this, arguments);

            this.collections = options.collections;
            this.listenTo(this.model, 'change', this.render);
            this.listenTo(this.model, 'destroy', function() {
                this.$el.remove();
            });
        },

        render: function() {
            this.$el.html(this.template(this.model.toJSON()));

            if (!this.model.get("_removable"))
                this.$("div[name=dv_remove_row]").hide();
            return this;
        },

        editTemplate: function() {
//            alert('edit a model is clicked!');
            var dlg = new EditTemplateDialog({
                el: $("#f5_bigip_template_edit_dialog"),
                model: this.model
            }).render();
            dlg.modal();
        },

        deleteTemplate: function() {
//            alert("delete dialog!");
            //this.model.destroy();
            if(confirm('Are you sure you want to delete the template "' + this.model.get("name")+'"?')){
                this.model.url = this.collections.url + "/" + this.model.get("id");
                //this.collections.remove();//
                this.model.destroy({
                    wait: true,
                    error: function(model,response){
                        var rsp=response.responseText;
                        var rspx=rsp.substring(rsp.indexOf('<body>'),rsp.length)
                            .replace(new RegExp('<(/?)(h1|p|html|body)([^>]*)>','g'),'<$1div$3>')
                            .replace(new RegExp('<[^>]*/>','g'),'');
                        var splunk_error_page=$(rspx);
                        var status=splunk_error_page.find('.status').text();
                        var msg=splunk_error_page.find('.msg').text();
                        alert(status+':\n'+msg);
                    },success: function(){
                    }
                } );
            }
        }

    });

});
