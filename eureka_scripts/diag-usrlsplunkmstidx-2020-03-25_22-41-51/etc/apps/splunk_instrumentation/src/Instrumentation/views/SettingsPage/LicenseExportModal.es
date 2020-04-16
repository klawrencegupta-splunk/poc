const ExportModal = require('./ExportModal');
module.exports = ExportModal.extend({
    moduleId: module.id,
    titleTemplate: '<%= _("Export/Send License Usage Data").t() %>',
    getSendDataStrategy() {
        return this.dataSendingService.sendLicenseData.bind(this.dataSendingService);
    },
    getExportDataStrategy() {
        return this.dataSendingService.exportLicenseData.bind(this.dataSendingService);
    },
});
