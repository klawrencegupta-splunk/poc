define([
    "jquery",
    "underscore",
    "backbone",
    "contrib/text!app/templates/ServersTable/Table.html",
    "app/views/ServersTable/Row"

], function(
    $,
    _,
    Backbone,
    ServersTableTableTemplate,
    ServersTableRow
){
    return Backbone.View.extend({
        el: ServersTableTableTemplate,

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
          var row = new ServersTableRow({model: server, collections: this.model});
          this.$el.children("tbody").get(0).appendChild(row.render().el);
        },

        addAll: function() {
            this.model.each(this.addOne, this);

            $(this.container).html(this.el);
        }

    });




});
