var style = require('./LicenseDataOptOutModal.pcss'),
    DocLink = require('Instrumentation/views/controls/DocLink'),
    ConfirmationModal = require('Instrumentation/views/controls/ConfirmationModal');

module.exports = ConfirmationModal.extend({
    moduleId: module.id,
    titleTemplate: '<%= _("License Usage Sharing").t() %>',
    bodyTemplate:
        '<div class="license-opt-out-modal-body"> \
            <div class="alert-warning"><i class="icon-alert"></i></div> \
            <div>\
                <p> \
                    <%= _("Disabling will prevent Splunk from automatically verifying license usage.").t() %> \
                    <%= _("If you disable this and your license requires verification, you must either manually initiate transmissions, or export this data to a file and share with Splunk.").t() %> \
                    <span class="license_instrumentation_doc_link" data-component="disableDataDocLink"></span>\
                </p> \
                <p><%= _("Are you sure you want to disable license usage sharing?").t() %></p> \
            </div>\
        </div>',
    footerTemplate: '<button class="pull-left btn btn-primary cancel"><%= _("Cancel").t() %></button> <button class="btn btn-other confirm"><%= _("Disable").t() %></button>',
    cancelButtonSelector: 'button.cancel',
    confirmButtonSelector: 'button.confirm',
    components: {
        disableDataDocLink: function () {
            return new DocLink({location: 'learnmore.usage.instrumentation.confirm'});
        }
    }
});
