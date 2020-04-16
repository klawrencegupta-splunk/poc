import constants from 'splunk_instrumentation/SWA/constants';
import Dispatcher from 'splunk_instrumentation/SWA/services/Dispatcher';
import Cache from 'splunk_instrumentation/SWA/services/Cache';
import RecoveryHandler from 'splunk_instrumentation/SWA/handlers/RecoveryHandler';
import ApiHandler from 'splunk_instrumentation/SWA/handlers/ApiHandler';
import PageHandler from 'splunk_instrumentation/SWA/handlers/PageHandler';
import EventQueue from 'splunk_instrumentation/SWA/services/EventQueue';
import { SessionHandler } from 'splunk_instrumentation/SWA/handlers/SessionHandler';

export default class SWACore {
    constructor(options) {
        if (!this.isLocalStorageAvailable()) {
            /* Stop SWA from running if there is no localStorage (happens in Safari Private Browsing Session)
             * will try to fix this in the future.
             * */
            return;
        }
        this.handlers = {};
        this._options = {};
        this.updateOptions(constants);
        this._options.updateOptions = this.updateOptions.bind(this);
        this._options.log = this.log.bind(this);
        this.updateOptions(options);
        this.registerHandler('SessionHandler', SessionHandler);
        this.registerHandler('RecoveryHandler', RecoveryHandler);
        this.registerHandler('ApiHandler', ApiHandler);
        this.registerHandler('PageHandler', PageHandler);

        this._options.cache = this._options.cache || new Cache(this._options);
        this._options.dispatcher = this._options.dispatcher || new Dispatcher(this._options);
        this._options.eventQueue = this._options.eventQueue ||
            new EventQueue(this._options, this._options.dispatcher);
        this._options.factory = this._options.eventQueue.factory;
        this.loadHandlers();
    }

    updateOptions(options) {
        // Overrides/extends default options.
        // Only certain options are available to override.

        [
            'bundleDataFunction',
            'eventRecovery',
            'cache',
            'cacheKey',
            'deploymentID',
            'dispatcher',
            'eventParser',
            'eventQueue',
            'factory',
            'maxQueueSize',
            'mintUuid',
            'log',
            'logging',
            'queueFailureMax',
            'experienceIDKey',
            'updateOptions',
            'userID',
            'cookieRegex',
            'experienceID',
            'savedTokenKey',
            'url',
            'version',
            'instanceGUID'
        ].forEach((key) => {
            if ('undefined' !== typeof options[key]) {
                this._options[key] = options[key];
            }
        });

        for (var name in options.handlers) {
            this.registerHandler(name, options.handlers[name]);
        }
    }

    registerHandler(name, handler) {
        this.handlers[name] = { handler };
        if (handler.init) {
            handler.init(this._options);
        }

    }

    loadHandlers() {
        Object.keys(this.handlers).forEach((key) => {
            const handler = this.handlers[key];
            if (!handler.loaded) {
                try {
                    handler.handler(this._options.factory, this._options);
                }
                finally {
                    handler.loaded = true;
                }
            }
        });
    }

    log() {
        if (this._options.devMode || this._options.logging) {
            console.log.apply(console, arguments);
        }
    }

    isLocalStorageAvailable() {
        try {
            localStorage.setItem("is", "available"); 
        }
        catch(e) {
            return false;
        }
        return true;
    }


    getOption(key) {
        return this._options[key];
    }
}

window.SWA = window.SWA || SWACore;
