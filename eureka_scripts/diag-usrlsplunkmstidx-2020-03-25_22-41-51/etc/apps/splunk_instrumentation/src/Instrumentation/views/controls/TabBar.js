var Component = require('Instrumentation/framework/Component'),
    TabBase = require('views/shared/tabcontrols/TabBase'),
    TabbedViewStack = require('views/shared/tabcontrols/TabbedViewStack');

module.exports = Component.extend({
    name: 'TabbedViewComponent',

    moduleId: module.id,

    tagName: 'ul',

    className: "nav nav-tabs main-tabs",

    template: '\
        <% collection.each(function (tabModel, i) { %> \
            <li class="tab-list-item <%=  tabModel.get("selected") ? "active" : "" %>" \
                data-tab-name="<%= tabModel.get("label") %>"\
                data-tab-number="<%= i %>"\
              >\
                <a class="tab-label"><%= tabModel.get("label") %></a>\
            </li>\
        <% }); %>',

    events: {
        'click .tab-label': 'selectTab'
    },

    initialize: function () {
        Component.prototype.initialize.apply(this, arguments);
        if (!this.collection) {
            throw new Error("Expected a collection of TabBase compatible models");
        }
    },

    selectTab: function (e) {
        var selectedTabNumber = parseInt($(e.target.parentElement).attr('data-tab-number'), 10);
        this.collection.each(function (tabModel, i) {
            tabModel.set('selected', i === selectedTabNumber);
        }.bind(this));
    },
});
