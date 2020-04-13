define([
    "jquery",
    "underscore",
    "backbone",
    "contrib/text!app/templates/TasksTable/Header.html"
], function(
    $,
    _,
    Backbone,
    ServersTableHeaderTemplate
){
    return Backbone.View.extend({
        tagName: "tr",
        template: ServersTableHeaderTemplate,

        render: function() {
            if (this.model)
                this.$el.html(_.template(this.template)(this.model.toJSON()));
            else
                this.$el.html(this.template);

          return this;
        }

    });




});
