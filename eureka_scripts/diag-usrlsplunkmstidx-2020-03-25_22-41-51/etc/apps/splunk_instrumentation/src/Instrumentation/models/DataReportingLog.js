var Model = require('Instrumentation/framework/Model');

var _super = Model;
module.exports = _super.extend({
    dateRangeDisplayString: function () {
        var startTime = new Date(this.get('start') * 1000),
            endTime = new Date(this.get('end') * 1000);

        return startTime.getFullYear()
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
    },

    timeDisplayString: function () {
        var time = new Date(this.get('_time'));

        return (time.getFullYear() +
            '-' +
            ('0' + (time.getMonth() + 1)).slice(-2) +
            '-' +
            ('0' + time.getDate()).slice(-2) +
            ' ' +
             time.toLocaleTimeString()
         );
    }
});
