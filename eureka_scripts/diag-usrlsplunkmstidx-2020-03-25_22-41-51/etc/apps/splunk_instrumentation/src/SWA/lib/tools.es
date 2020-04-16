/**
 * Created by adrianj on 11/16/16.
 */

const shallowProperty = function (key) {
    return function (obj) {
        return obj == null ? void 0 : obj[key];
    };
};


// Helper for collection methods to determine whether a collection
// should be iterated as an array or as an object.
// Related: http://people.mozilla.org/~jorendorff/es6-draft.html#sec-tolength
// Avoids a very nasty iOS 8 JIT bug on ARM-64. #2094
const MAX_ARRAY_INDEX = Math.pow(2, 53) - 1;
const getLength = shallowProperty('length');
const isArrayLike = function (collection) {
    const length = getLength(collection);
    return typeof length === 'number' && length >= 0 && length <= MAX_ARRAY_INDEX;
};


// Collection Functions
// --------------------

// The cornerstone, an `each` implementation, aka `forEach`.
// Handles raw objects in addition to array-likes. Treats all
// sparse array-likes as if they were dense.
const each = function (obj, piteratee, context) {
    const iteratee = context ? piteratee.bind(context) : piteratee;
    let i;
    let length;
    if (isArrayLike(obj)) {
        for (i = 0, length = obj.length; i < length; i++) {
            iteratee(obj[i], i, obj);
        }
    } else {
        const keys = Object.keys(obj);
        for (i = 0, length = keys.length; i < length; i++) {
            iteratee(obj[keys[i]], keys[i], obj);
        }
    }
    return obj;
};

const isArray = Array.isArray || function (obj) {
        return toString.call(obj) === '[object Array]';
};

const pick = function (obj, keys) {
    const results = {};
    each(keys, (key) => {
        if (obj[key]) {
            results[key] = obj[key];
        }
    });
    return results;
};

export default {
    each,
    isArray,
    pick,
};
