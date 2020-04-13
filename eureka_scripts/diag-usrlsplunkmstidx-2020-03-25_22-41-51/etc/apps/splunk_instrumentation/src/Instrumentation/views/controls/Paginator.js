var Model = require('Instrumentation/framework/Model'),
    Component = require('Instrumentation/framework/Component'),
    CollectionPaginator = require('views/shared/CollectionPaginator'),
    SelectPageCount = require('views/shared/dataenrichment/preview/components/SelectPageCount.js');

var _super = Component;

/**
 * Usage:
 *
 *  var paginator = new Paginator({
 *      model: new Model({
 *          count: ITEMS_PER_PAGE,
 *          offset: INDEX_OF_FIRST_ELEMENT_TO_SHOW
 *      })
 *  }).render();
 */
module.exports = _super.extend({
    name: 'Paginator',

    template: '<div class="page-count-selector pull-right"></div><div class="paginator-container"></div>',

    initialize: function () {
        _super.prototype.initialize.apply(this, arguments);

        if (!this.model) {
            throw new Error("No model provided");
        }
    },

    beforeFirstRender: function () {
        this.children = this.children || {};

        if (!this.model.has("count")) {
            this.model.set('count', 10);
        }

        if (!this.model.has("currentPage")) {
            this.model.set('currentPage', 0);
        }

        this.children.paginator = new CollectionPaginator({
            collection: this.collection,
            model: this.model,
            offsetAttr: 'offset',
            countAttr: 'count'
        });

        this.children.paginator.model.on('change', function () {
            this.children.paginator.render();
        }.bind(this));

        this.children.paginator.render();

        this.addPageCountSelector();
    },

    /**
     * After we render our own template, we'll manually insert our children.
     */
    afterRender: function () {
        this.$('.paginator-container').append(this.children.paginator.$el);
        this.$('.page-count-selector').append(this.children.pageCountSelector.$el);
    },

    /**
     * Components get moved around, and have their events re-delegated so
     * they continue working properly. We'll have to tell our "dumb" view
     * children about this event so they keep working, too.
     */
    delegateEvents: function () {
        _super.prototype.delegateEvents.apply(this, arguments);
        if (this.children) {
            this.children.paginator && this.children.paginator.delegateEvents();

            // The SelectPageCount control is not well-behaved as far as delegating events
            // is concerned, so we'll have to re-create it each time for now.
            this.addPageCountSelector();
        }
    },

    addPageCountSelector: function () {
        this.children.pageCountSelector = new SelectPageCount();

        this.children.pageCountSelector.on('change', function () {
            this.model.set('count', parseInt(this.children.pageCountSelector.getValue()));
        }.bind(this));

        this.children.pageCountSelector.render();
        this.$('.page-count-selector').empty().append(this.children.pageCountSelector.$el);

        // The selector expects its value as a string (so the .toString call is significant)
        this.children.pageCountSelector.setValue(this.model.get('count').toString());
    }
});
