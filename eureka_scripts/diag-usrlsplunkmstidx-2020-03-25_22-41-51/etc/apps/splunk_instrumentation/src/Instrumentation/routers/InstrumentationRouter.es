require('splunk_instrumentation/Instrumentation/views/common.pcss');

const _ = require('underscore');
const $ = require('jquery');
const Router = require('splunk_instrumentation/Instrumentation/framework/Router');
const SettingsPage = require('splunk_instrumentation/Instrumentation/views/SettingsPage');
const LogsPage = require('splunk_instrumentation/Instrumentation/views/LogsPage');
const ErrorPage = require('splunk_instrumentation/Instrumentation/views/ErrorPage');
const environment = require('splunk_instrumentation/Instrumentation/services/environment');
const Model = require('splunk_instrumentation/Instrumentation/framework/Model');
const InstrumentationService =
    require('splunk_instrumentation/Instrumentation/services/InstrumentationService');
const splunkd = require('splunk_instrumentation/Instrumentation/services/splunkd');

module.exports = Router.extend({
    pages: {
        instrumentation_index: SettingsPage,
        instrumentation_logs: LogsPage,
    },
    initialize(...args) {
        Router.prototype.initialize.apply(this, args);
        this.setPageTitle(_('Instrumentation').t());
        $(document).on('click', 'a', this.onClickLink.bind(this));
        this.enableAppBar = false;
        this.fetchUser = true;
        this.instrumentationService = new InstrumentationService();
    },
    page(locale, app, page) {
        Router.prototype.page.apply(this, arguments);
        const PageType = this.pages[page];
        const root = this.model.application.get('root');

        if (PageType) {
            $.when(
                this.deferreds.application,
                this.deferreds.user,
                this.deferreds.pageViewRendered,
                this.instrumentationService.getInstrumentationEligibility(root)
            ).done(_(function pageDependenciesLoaded(
                application,
                user,
                pageViewRendered,
                instrumentationEligibility
            ) {
                environment.set({
                    application: this.model.application,
                    user: this.model.user,
                    router: this,
                });

                $('.preload').replaceWith(this.pageView.el);

                if (this.activeView) {
                    this.activeView.remove();
                }

                // When we're doing a full rebuild of the page
                // (after a `navigate` w/ trigger option set to true),
                // make sure we scroll back to the origin (as if an
                // actual page refresh had happened).
                window.scrollTo(0, 0);
                if (instrumentationEligibility.is_eligible) {
                    this.activeView = new PageType().render();
                } else {
                    this.activeView = new ErrorPage({
                        model: new Model({
                            level: 'warning',
                            message: instrumentationEligibility.reason === 'UNAUTHORIZED' ?
                                _("You're not authorized to view this page.").t() :
                                _('Instrumentation settings are not accessible on this server.' +
                                  ' Please access the settings from a search head.').t(),
                        }),
                    }).render();
                }
                this.pageView.$('.main-section-body').append(this.activeView.el);
            }).bind(this));
        } else {
            Router.prototype.notFound.apply(this, arguments);
        }
    },

    /**
     * If a link is left-clicked (with no ctrl/meta keys down),
     * and the href appears to point inside of this app, and has the
     * trigger-route attribute set, navigate there & trigger the route
     * handler. Otherwise allow event to pass through to the default
     * event handler.
     */
    onClickLink(event) {
        const target = event.target;
        if (target.href
                && target.href.indexOf(window.location.origin + splunkd.routes.manager('')) === 0
                && $(target).is('[trigger-route]')) {
            if (event.which === 1 && !event.metaKey && ! event.ctrlKey) {
                event.preventDefault();
                this.navigate(target.href.slice(window.location.origin.length), { trigger: true });
            }
        }
    },
});
