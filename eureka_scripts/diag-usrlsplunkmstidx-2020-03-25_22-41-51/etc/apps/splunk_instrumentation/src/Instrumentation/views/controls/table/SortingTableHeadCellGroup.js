var _ = require('underscore'),
    Backbone = require('backbone'),
    $ = require('jquery');

/**
 * Coordinates sort events among a group of SortingTableHeadCell's.
 * When one of the cells emits a 'sorted' event, the other cells sort order is unset.
 *
 * Usage:
 *   var group = new SortingTableHeadCellGroup();
 *   var header1 = new SortingTableHeadCell({model: {sortOrder: null} });
 *   var header2 = new SortingTableHeadCell({model: {sortOrder: null} });
 *   group.add('key1', header1);
 *   group.add('key2', header2);
 *
 * When any of the components in the group trigger a 'sorted' event, the group
 * will trigger a 'sorted' event as well, with the child compoent as the argument
 * to any event handlers.
 */
var SortingTableHeadCellGroup = function () {
    this.headerComponents = {};
};

var _proto = SortingTableHeadCellGroup.prototype = {};
_.extend(_proto, Backbone.Events);

/**
 * Add a new header to the group.
 * Accepts an object, with mapping from keys to SortingTableHeadCell components,
 * -or- a single key, and a single component.
 *
 * Note: keys are provided for each view to allow views to be replaced, while
 *       ensuring that event handlers are cleaned correctly.
 */
_proto.add = function (name, component) {
    this._stopListeningForSortEvents();
    if (typeof name == 'object') {
        _.keys(name).forEach(function (k) {
            this.headerComponents[k] = name[k];
        }.bind(this));
    } else {
        this.headerComponents[name] = component;
    }
    this._listenForSortEvents();
};

_proto._stopListeningForSortEvents = function () {
    _.values(this.headerComponents).forEach(function (header) {
        this.stopListening(header);
    }.bind(this));
};

_proto._listenForSortEvents = function () {
    _.values(this.headerComponents).forEach(function (thisHeader) {
        this.listenTo(thisHeader, 'sorted', function () {
            _.values(this.headerComponents).forEach(function (otherHeader) {
                if (otherHeader != thisHeader) {
                    otherHeader.model.set('sortOrder', null);
                }
            });
            this.trigger('sorted', thisHeader);
        }.bind(this));
    }.bind(this));
};

module.exports = SortingTableHeadCellGroup;