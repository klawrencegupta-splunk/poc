const constants = {};

/**********************************************************************************************************************/
/* GENERAL SWA SETTINGS                                                                                               */
/**********************************************************************************************************************/
constants.CACHE_NAME = 'mintjs:cache';

constants.MAX_QUEUE_SIZE = 10;

constants.MINT_UUID = '123';

constants.EXPERIENCE_ID_KEY = 'experience_id';

constants.COOKIE_REGEX = /splunkweb_csrf_token_[0-9]+=[\S;]*/g;

constants.SAVED_TOKEN_KEY = 'token_key';

// Can't rely on $C existing if we're loaded in a 3rd-party
// page (perhaps served by a custom controller), so check first.
constants.LOCALE = window.$C && window.$C.LOCALE;

// If we can't find the locale, we're in a strange place.
// We'll use this to skip certain logic that requires a familiar
// page context as usually provided by splunkweb.
constants.FOREIGN_PAGE_CONTEXT = !constants.LOCALE;

// Capture Groups: 1 = app name, 2 = page string
// Page string will exclude any ?query=params or #anchors from the URL
constants.APP_PAGE_DATA_REGEXP = new RegExp(`${constants.LOCALE}/app/([^#?/]+)/([^#?]*)`);

// Capture Groups: 1 = page string - which is the location string
constants.HELP_PAGE_DATA_REGEXP = new RegExp(`${constants.LOCALE}/help\\?(?:.+&)?location=([^&]*)`);

// Capture Groups: 1 = page string
// System pages are all those not under the /help/ or /app/ namespaces
constants.SYSTEM_PAGE_DATA_REGEXP = new RegExp(`${constants.LOCALE}/([^#?]*)`);

constants.SYSTEM_APP_NAME = '$SPLUNK_PLATFORM';

// Capture Groups: 1 = page string prefix, 2 = username, 3 = page string suffix
// Capture group 2 should be excluded if this regexp matches a URL to be reported.
// If editing, be mindful the capture group protocol listed above.
//  - You can use (?:non-capturing-groups) to group without capturing,
//    and thus avoid affecting the protocol.
constants.USERNAME_OBSCURE_REGEXP = new RegExp(
    // Match the locale segment
    `${constants.LOCALE}/` +

    // Match group #1 - the page string preceding the username
    `(manager/[^/]+/authentication/(?:users|changepassword)/)` +

    // Match group #2 - the username segment
    `([^/#?]+)` +

    // Match group #3 - the rest of the page string excluding any query params or anchors.
    // Should match the empty string in case of no trailing segment
    `(/?[^#?]*)`
);

/**********************************************************************************************************************/
/* DEV MODE OPTIONS                                                                                                   */
/**********************************************************************************************************************/

/**
 * Enables dev mode.
 */
constants.DEV_MODE = false;

/**
 * Enables logging
 * @type {boolean}
 */
constants.ENABLE_LOGGING = false;

/**
 * Logs event sending on dev mode.
 * @constructor
 */
constants.LOG = (...args)=>{
    if (constants.DEV_MODE || constants.ENABLE_LOGGING) {
        console.log.call(console, ...args);
    }
};

/**********************************************************************************************************************/
/* HELPER FUNCTIONS                                                                                                   */
/**********************************************************************************************************************/
/**
 * Define a function that returns stringified data.
 * (events) => {
 *     return events.toString();
 * }
 *
 * Set to 'CDS' to use internal function to bundle data for CDS. Default.
 * Set to null to use basic stringify.
 *
 * @param events
 * @returns {string|*}
 * @constructor
 */
constants.BUNDLE_DATA_FUNCTION = 'CDS';

/**
 * Parses a JSON string to an Event.
 * @param key
 * @param val
 * @returns {*}
 * @constructor
 */
/*constants.EVENT_PARSER = (key, val) => {
    if (typeof(val) === 'object' && val.__type == "Event") {
        return new Event(val);
    }
    return val;
}*/

/**********************************************************************************************************************/
/* EXPORT                                                                                                             */
/**********************************************************************************************************************/
export default {
    cacheKey : "swa_js_recovery",
    queueFailureMax : 200,
    baseURL: constants.BASE_URL,
    bundleDataFunction: constants.BUNDLE_DATA_FUNCTION,
    devMode: constants.DEV_MODE,
    devURL: constants.DEV_URL, // Set null to not send data
    log: constants.LOG,
    logging: constants.ENABLE_LOGGING,
    maxQueueSize: constants.MAX_QUEUE_SIZE,
    mintUuid: constants.MINT_UUID,
    experienceIDKey: constants.EXPERIENCE_ID_KEY,
    cookieRegex: constants.COOKIE_REGEX,
    savedTokenKey: constants.SAVED_TOKEN_KEY,

    LOCALE: constants.LOCALE,
    FOREIGN_PAGE_CONTEXT: constants.FOREIGN_PAGE_CONTEXT,
    APP_PAGE_DATA_REGEXP: constants.APP_PAGE_DATA_REGEXP,
    HELP_PAGE_DATA_REGEXP: constants.HELP_PAGE_DATA_REGEXP,
    SYSTEM_PAGE_DATA_REGEXP: constants.SYSTEM_PAGE_DATA_REGEXP,
    USERNAME_OBSCURE_REGEXP: constants.USERNAME_OBSCURE_REGEXP,
    SYSTEM_APP_NAME: constants.SYSTEM_APP_NAME
};
