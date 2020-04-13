const ExportModal = require('./ExportModal');
module.exports = ExportModal.extend({
    moduleId: module.id,
    titleTemplate: '<%= _("Export/Send Anonymous Usage Data").t() %>',
    getSendDataStrategy() {
        return this.dataSendingService.sendAnonymousData.bind(this.dataSendingService);
    },
    getExportDataStrategy() {
        return this.dataSendingService.exportAnonymousData.bind(this.dataSendingService);
    },
});
