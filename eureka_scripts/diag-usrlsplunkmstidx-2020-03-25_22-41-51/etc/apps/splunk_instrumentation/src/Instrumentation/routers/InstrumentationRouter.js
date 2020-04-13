var _ = require('underscore'),
    Backbone = require('backbone'),
    globalStyles = require('Instrumentation/views/common.pcss'),
    $ = require('jquery'),
    Router = require('Instrumentation/framework/Router'),
    SettingsPage = require('Instrumentation/views/SettingsPage'),
    LogsPage = require('Instrumentation/views/LogsPage'),
    ErrorPage = require('Instrumentation/views/ErrorPage'),
    environment = require('Instrumentation/services/environment'),
    Model = require('Instrumentation/framework/Model'),
    InstrumentationService = require('Instrumentation/services/InstrumentationService');

module.exports = Router.extend({
    routes: {
        ':locale/manager/:app/instrumentation_index': 'gotoIndex',
        ':locale/manager/:app/instrumentation_logs(#:hash)': 'gotoLogs',
        '*root/:locale/manager/:app/instrumentation_index': 'gotoRootedIndex',
        '*root/:locale/manager/:app/instrumentation_logs(#:hash)': 'gotoRootedLogs',
        '*splat': 'notFound'
    },
    permalinks: {
        get appRoot() {
            var application = environment.get('application'),
                root = application.get('root');
            return (root ? '/' + root : '') + '/' + application.get('locale') + '/manager/' + application.get('app');
        },
        get settingsPage() {
            return this.appRoot + '/instrumentation_index'
        },
        get anonymousDataLogs() {
            return this.appRoot + '/instrumentation_logs?dataType=anonymous';
        },
        get licenseDataLogs() {
            return this.appRoot + '/instrumentation_logs?dataType=license';
        }
    },
    initialize: function() {
        Router.prototype.initialize.apply(this, arguments);
        this.setPageTitle(_('Instrumentation').t());
        $(document).on('click', 'a', this.onClickLink.bind(this));
        this.enableAppBar = false;
        this.fetchUser = true;
        this.instrumentationService = new InstrumentationService();
    },
    page: function(locale, app, page, pageType) {
        Router.prototype.page.apply(this, arguments);
        $.when(
            this.deferreds.application
        ).done(_(function (
            application
        ) {
            // Set application root before pageView is resolved.
            if (this.root) {
                this.model.application.set({
                    root: this.root
                }, {silent: true});
            }
            $.when(
                this.deferreds.user,
                this.deferreds.pageViewRendered,
                this.instrumentationService.getInstrumentationEligibility(this.root)
            ).done(_(function (
                user,
                pageViewRendered,
                instrumentationEligibility
            ) {
                environment.set({
                    application: this.model.application,
                    user: this.model.user,
                    router: this
                });

                $('.preload').replaceWith(this.pageView.el);

                if (this.activeView) this.activeView.remove();

                // When we're doing a full rebuild of the page (after a `navigate` w/ trigger option
                // set to true), make sure we scroll back to the origin (as if an actual page refresh
                // had happened).
                window.scrollTo(0, 0);

                if (instrumentationEligibility.is_eligible) {
                    this.activeView = new pageType().render();
                } else {
                    this.activeView = new ErrorPage({
                        model: new Model({
                            level: 'warning',
                            message: instrumentationEligibility.reason == 'UNAUTHORIZED' ?
                                _("You're not authorized to view this page.").t() :
                                _("Instrumentation settings are not accessible on this server. Please access the settings from a search head.").t()
                        }),
                    }).render();
                }
                this.pageView.$('.main-section-body').append(this.activeView.el);
            }).bind(this));
        }).bind(this));
    },

    setRoot: function(root) {
        this.root = root;
    },

    gotoIndex: function (locale, app) {
        this.page(locale, app, 'index', SettingsPage);
    },

    gotoRootedIndex: function (root, locale, app) {
        this.setRoot(root);
        this.gotoIndex(locale, app);
    },

    gotoLogs: function (locale, app, dataType) {
        this.page(locale, app, 'logs', function () { return new LogsPage({dataType: dataType}); });
    },

    gotoRootedLogs: function (root, locale, app, dataType) {
        this.setRoot(root);
        this.gotoLogs(locale, app, dataType);
    },
    
    /**
     * If a link is left-clicked (with no ctrl/meta keys down),
     * and the href appears to point inside of this app, and has the
     * trigger-route attribute set, navigate there & trigger the route
     * handler. Otherwise allow event to pass through to the default
     * event handler.
     */
    onClickLink: function (event) {
        var target = event.target;
        if (target.href 
                && target.href.indexOf(window.location.origin + this.permalinks.appRoot) == 0
                && $(target).is('[trigger-route]')) {
            if (event.which == 1 && !event.metaKey && ! event.ctrlKey) {
                event.preventDefault();
                this.navigate(target.href.slice(window.location.origin.length), { trigger: true });
            }
        }
    }
});
