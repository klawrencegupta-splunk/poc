define(
    [
        'jquery',
        'underscore',
        'routers/Base',
        'splunk_monitoring_console/models/splunk_health_check/DmcConfigs',
        'splunk_monitoring_console/views/splunk_health_check_list/PageController'
    ],
    function(
        $,
        _,
        BaseRouter,
        DmcConfigsModel,
        PageController
    ) {
        return BaseRouter.extend({
            initialize: function() {
                BaseRouter.prototype.initialize.apply(this, arguments);

                // this is needed
                this.fetchAppLocals = true;


                this.model.dmcConfigs = new DmcConfigsModel({}, {
                    appLocal: this.model.appLocal,
                    serverInfo: this.model.serverInfo
                });
            },
            page: function(locale, app, page) {
                BaseRouter.prototype.page.apply(this, arguments);

                this.setPageTitle(_('Health Check Items').t());

                $.when(
                    this.model.dmcConfigs.fetch(),
                    this.deferreds.pageViewRendered
                ).done(function() {
                    $('.preload').replaceWith(this.pageView.el);

                    if (this.pageController) {
                        this.pageController.detach();
                    }
                    this.pageController = new PageController({
                        model: this.model,
                        collection: this.collection
                    });
                    this.pageView.$('.main-section-body').append(this.pageController.render().el);
                }.bind(this));
            }
        });
    }
);