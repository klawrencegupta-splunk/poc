const Model = require('splunk_instrumentation/Instrumentation/framework/Model');

const _super = Model;
module.exports = _super.extend({
    dateRangeDisplayString() {
        let result = '';
        if (this.get('start_date')) {
            result = this.get('start_date');
            if (this.get('end_date') && (this.get('end_date') !== this.get('start_date'))) {
                result += ` to ${this.get('end_date')}`;
            }
        } else {
            const startTime = new Date(this.get('start') * 1000);
            const endTime = new Date(this.get('end') * 1000);

            result = startTime.getFullYear()
                + '-'
                + ('0' + (startTime.getMonth() + 1)).slice(-2)
                + '-'
                + ('0' + startTime.getDate()).slice(-2)
                + ' to '
                + endTime.getFullYear()
                + '-'
                + ('0' + (endTime.getMonth() + 1)).slice(-2)
                + '-'
                + ('0' + endTime.getDate()).slice(-2);
        }
        return result;
    },

    timeDisplayString() {
        return this.get('time_formatted');
    },
});
