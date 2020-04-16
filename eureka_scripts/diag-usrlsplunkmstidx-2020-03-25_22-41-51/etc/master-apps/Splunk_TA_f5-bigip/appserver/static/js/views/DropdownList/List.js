define([
    "jquery",
    "underscore",
    "backbone",
    "app/views/DropdownList/Item",
    "contrib/text!app/templates/DropdownList/List.html"
], function(
    $,
    _,
    Backbone,
    DropdownlistItem,
    ListTemplate
){
    return Backbone.View.extend({
        el: ListTemplate,
        defaultValue: null,

        initialize: function(options) {
            this.listenToOnce(this.model, 'sync', this.addAll);
            if (options.defaultValue != undefined)
                this.defaultValue = options.defaultValue;
        },

        render: function(event, options) {
            return this;
        },

        addOne: function(item) {
          var itemview = new DropdownlistItem({model: item});
          this.$el.append(itemview.render().el);
        },

        addAll: function() {
            this.model.each(this.addOne, this);
            if (this.defaultValue != null)
                this.select(this.defaultValue);
        },

        select: function(name) {
            this.$("option[value=" + name + "]").attr("selected", "selected");
        },

        getSelection: function() {
            return this.$el.val();
        }

    });




});
