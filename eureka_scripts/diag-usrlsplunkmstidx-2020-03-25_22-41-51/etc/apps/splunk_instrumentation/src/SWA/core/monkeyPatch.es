function monkeyPatch(obj, field, value) {
    if (typeof obj[field] === 'undefined') {
        obj[field] = value;
    }
}

monkeyPatch(Object, 'assign', require('core-js/library/fn/object/assign'));
monkeyPatch(Array, 'isArray', require('core-js/library/fn/array/is-array'));
