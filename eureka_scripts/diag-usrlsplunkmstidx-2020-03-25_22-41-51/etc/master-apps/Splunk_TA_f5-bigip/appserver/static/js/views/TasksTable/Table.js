define([
    "jquery",
    "underscore",
    "backbone",
    "contrib/text!app/templates/TasksTable/Table.html",
    "app/views/TasksTable/Row"

], function(
    $,
    _,
    Backbone,
    TasksTableTableTemplate,
    TasksTableRow
){
    return Backbone.View.extend({
        el: TasksTableTableTemplate,

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
          var row = new TasksTableRow({model: server, collections: this.model});
          this.$el.children("tbody").get(0).appendChild(row.render().el);
        },

        addAll: function() {
            this.model.each(this.addOne, this);

            $(this.container).html(this.el);
        }

    });




});
