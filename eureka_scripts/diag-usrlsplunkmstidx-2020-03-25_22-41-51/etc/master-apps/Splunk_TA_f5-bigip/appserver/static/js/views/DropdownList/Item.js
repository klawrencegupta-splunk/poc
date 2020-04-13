define([
    "jquery",
    "underscore",
    "backbone"
], function(
    $,
    _,
    Backbone
){
    return Backbone.View.extend({

        tagName: "option",

        render: function() {
            var name = this.model.get("name");
            this.$el.html(name);
            this.$el.attr("value", name);

            return this;
        }

    });

});
