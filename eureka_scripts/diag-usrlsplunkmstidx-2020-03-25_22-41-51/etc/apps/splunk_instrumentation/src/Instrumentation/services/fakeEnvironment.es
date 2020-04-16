const environment = require('splunk_instrumentation/Instrumentation/services/environment');
const fakeEnvironment = module.exports = {};

let clobbered = false;

/**
 * Stubs the models usually found in the environment
 * - Intended for unit testing purposes only
 * - Should be used in a setup function. In teardown, call `restore` (see below).
 */
fakeEnvironment.create = function create() {
    clobbered = {};

    Object.keys(environment.attributes).forEach((k) => {
        clobbered[k] = environment.get(k);
    });

    const stubModel = {
        get(prop) {
            return `STUB-${prop}`;
        },
    };

    Object.keys(environment.attributes).forEach((k) => {
        environment.set(k, stubModel);
    });
};

/**
 * Restore the environment model to the state before `stub` was called.
 */
fakeEnvironment.restore = function restore() {
    if (!clobbered) return;

    Object.keys(environment.attributes).forEach((k) => {
        environment.set(k, clobbered[k]);
    });

    clobbered = false;
};

