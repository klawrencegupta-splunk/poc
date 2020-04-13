var Component = require('Instrumentation/framework/Component'),
    _ = require('underscore'),
    route = require('uri/route'),
    environment = require('Instrumentation/services/environment');

module.exports = Component.extend({
    name: 'DocLink',

    moduleId: module.id,

    tagName: 'span',

    template: '<a class="external" href="<%= href %>" target="_blank"><%= _("Learn More").t() %></a>',

    templateContext: function () {
        return { href: this.href };
    },

    initialize: function (opt) {
        Component.prototype.initialize.apply(this, arguments);

        var application = environment.get('application'),
            root = application.get('root'),
            locale = application.get('locale'),
            location = opt.location;

        this.href = route.docHelp(root, locale, location);
    }
});
