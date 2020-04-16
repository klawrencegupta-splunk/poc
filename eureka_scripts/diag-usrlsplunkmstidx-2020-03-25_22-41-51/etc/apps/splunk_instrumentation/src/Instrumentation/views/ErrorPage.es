const Component = require('splunk_instrumentation/Instrumentation/framework/Component');

module.exports = Component.extend({
    template: `
    <div class="section-padded section-header">
        <h1 class="section-title"><%= _("Instrumentation").t() %></h1>
    </div>
    <div class="panel main-logs-panel">
    <div class="instrumentation-error-panel">
        <div class="alert-<%= model.get("level") || "error" %>">
            <i class="icon-alert"></i>
            <p><%= model.get("message") %></p>
        </div>
    </div>
    `,
});
