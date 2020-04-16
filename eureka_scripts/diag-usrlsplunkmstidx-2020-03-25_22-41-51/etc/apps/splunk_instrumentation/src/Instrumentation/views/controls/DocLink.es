const Component = require('splunk_instrumentation/Instrumentation/framework/Component');
const route = require('uri/route');
const environment = require('splunk_instrumentation/Instrumentation/services/environment');

module.exports = Component.extend({
    name: 'DocLink',

    moduleId: module.id,

    tagName: 'span',

    template:
        '<a class="external" href="<%= href %>" target="_blank"><%= _("Learn More").t() %></a>',

    templateContext() {
        return { href: this.href };
    },

    initialize(opt) {
        Component.prototype.initialize.apply(this, arguments);

        const application = environment.get('application');
        const root = application.get('root');
        const locale = application.get('locale');
        const location = opt.location;

        this.href = route.docHelp(root, locale, location);
    },
});
