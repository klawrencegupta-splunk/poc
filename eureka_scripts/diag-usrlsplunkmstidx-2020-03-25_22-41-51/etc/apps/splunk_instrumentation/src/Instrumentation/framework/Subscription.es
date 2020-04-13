const Backbone = require('backbone');
const _ = require('underscore');
const VolatileExpression = require('./VolatileExpression');

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
    this.expr.on('change', () => {
        this.expr.evaluate();
    });
    this.expr.on('value', (value) => {
        this.value = value;
        this.trigger('change', value);
    });
    this.expr.evaluate();
}
_.extend(Subscription.prototype, Backbone.Events, {
    dispose() {
        this.expr.dispose();
    },
});

module.exports = Subscription;
