define([
    "jquery",
    "underscore",
    "backbone",
    "contrib/text!app/templates/TemplatesTable/Table.html",
    "app/views/TemplatesTable/Row"

], function(
    $,
    _,
    Backbone,
    TemplatesTableTableTemplate,
    TemplatesTableRow
){
    return Backbone.View.extend({
        el: TemplatesTableTableTemplate,

        initialize: function(options) {
            this.model = options.model;
            this.container = options.container;
            this.listenToOnce(this.model, 'sync', this.initAddAll);
        },

        initAddAll: function() {
            this.addAll();
            this.listenTo(this.model, 'add', this.onAdd);
        },

        render: function(event, options) {
            return this;
        },

        onAdd: function(args) {
            this.addOne(this.model.get(args.changed.id));

            return this;
        },

        addOne: function(server) {
          var row = new TemplatesTableRow({model: server, collections: this.model});
          this.$el.children("tbody").get(0).appendChild(row.render().el);
        },

        addAll: function() {
            this.model.each(this.addOne, this);

            $(this.container).html(this.el);
        }

    });




});
