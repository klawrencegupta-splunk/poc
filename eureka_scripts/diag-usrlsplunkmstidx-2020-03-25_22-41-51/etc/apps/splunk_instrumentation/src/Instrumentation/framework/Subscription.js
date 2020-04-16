var global_state = require('./global_state'),
    Backbone = require('backbone'),
    _ = require('underscore'),
    VolatileExpression = require('./VolatileExpression');

/**
 * Like a VolatileExpression, but always re-evaluates immediately and
 * triggers a 'change' event with the new value.
 *
 * Example
 *
 * ```JavaScript
 * var subscription = new Subscription(function () {
 *   return model.get('some').get('deep').get('attr');
 * });
 * subscription.on('change', function (val) {
 *   console.log('New value of expression is :' + val);
 * });
 * console.log('Last value was: ' + subscription.value);
 * subscription.dispose();
 * ```
 */
function Subscription(fn) {
    this.expr = new VolatileExpression(fn);
    this.expr.on('change', function () {
        this.expr.evaluate();
    }.bind(this));
    this.expr.on('value', function (value) {
        this.value = value;
        this.trigger('change', value);
    }.bind(this));
    this.expr.evaluate();
}
_.extend(Subscription.prototype, Backbone.Events, {
    dispose: function () {
        this.expr.dispose();
    }
});

module.exports = Subscription;
