var Component = require('Instrumentation/framework/Component');

module.exports = Component.extend({
    tagName: 'th',
    className: 'sorts',
    template: '<%= model.get("label")%> <i class="icon-sorts <%= model.get("sortOrder") || "" %>"></i>',
    events: {
        click: 'onClick'
    },
    onClick: function (opt) {
        switch (this.model.get('sortOrder')) {
            case 'asc': this.model.set('sortOrder', 'desc'); break
            case 'desc': this.model.set('sortOrder', null); break
            default: this.model.set('sortOrder', 'asc'); break
        }
        this.trigger('sorted');
    }
});