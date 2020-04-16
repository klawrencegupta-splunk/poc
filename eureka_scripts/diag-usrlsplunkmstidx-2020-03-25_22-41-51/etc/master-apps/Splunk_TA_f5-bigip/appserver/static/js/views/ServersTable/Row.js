define([
    "jquery",
    "underscore",
    "backbone",
    "bootstrap",
    "contrib/text!app/templates/ServersTable/Row.html",
    'app/views/Modals/EditServer'
], function(
    $,
    _,
    Backbone,
    Bootstrap,
    ServersTableRowTemplate,
    EditServerDialog
){
    return Backbone.View.extend({
        tagName: "tr",
        template: _.template(ServersTableRowTemplate),

        events: {
            "click a.update-item": "editServer",
            "click a.delete-item": "deleteServer"
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

            return this;
        },

        editServer: function() {
            var dlg = new EditServerDialog({
                el: $("#f5_bigip_server_edit_dialog"),
                model: this.model
            }).render();
            dlg.modal();
        },

        deleteServer: function() {
            if(confirm('Are you sure you want to delete the server "' + this.model.get("name")+'"?')){
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
