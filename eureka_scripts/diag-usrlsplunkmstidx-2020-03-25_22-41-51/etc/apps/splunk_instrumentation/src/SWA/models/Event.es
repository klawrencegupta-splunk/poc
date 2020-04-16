import constants from 'splunk_instrumentation/SWA/constants';

export default class Event {
    /**
     * Creates an Event. (All params are required)
     * @param {object} eventData - Event data.
     * @param {string} deploymentID - ID of the Deployment.
     * @param {string} experienceID - ID of the Session.
     * @param {string} userID - ID of the current user.
     * @returns {*}
     */
    constructor(eventData, experienceID, userID, deploymentID) {
        if (this._checkParams.apply(this, eventData)) {
            this._type = eventData.type;
            this.data = eventData.data || {};
            this.experienceID = eventData.experienceID || experienceID;
            this.userID = eventData.userID || userID;
            this._timestamp = eventData.timestamp || parseInt(Date.now() / 1000, 10);
            this.visibility = eventData.visibility || 'anonymous';
            this.deploymentID = eventData.deploymentID || deploymentID;
            this.eventID = eventData.eventID || this._generateExperienceID();

            if (!this.data.app || !this.data.page) {
                if (window && window.location) {
                    const pageData = Event.getPageData(Event.getURL());

                    if (!this.data.app) {
                        this.data.app = pageData.app;
                    }
                    if (!this.data.page) {
                        this.data.page = pageData.page;
                    }
                }
            }

            return this;
        }
        return null;
    }

    static getURL() {
        return window.location.href;
    }

    static getPageData(url) {
        const unknown = { app: 'UNKNOWN_APP', page: 'UNKNOWN_PAGE' };

        if (constants.FOREIGN_PAGE_CONTEXT) {
            // Couldn't find $C, no locale known,
            // no chance of parsing page data.
            // May happen when rendering pages
            // through 3rd party custom controllers.
            return unknown;
        }

        return Event.getHelpPageData(url) ||
            Event.getAppPageData(url) ||
            Event.getSystemPageData(url) ||
            unknown;
    }

    static getHelpPageData(url) {
        const match = url.match(constants.HELP_PAGE_DATA_REGEXP);
        if (match) {
            return { app: constants.SYSTEM_APP_NAME, page: 'help/' + match[1] };
        }
        return null;
    }

    static getAppPageData(url) {
        const match = url.match(constants.APP_PAGE_DATA_REGEXP);
        if (match) {
            return { app: match[1], page: match[2] };
        }
        return null;
    }

    static getSystemPageData(url) {
        const match = url.match(constants.SYSTEM_PAGE_DATA_REGEXP);

        if (match) {
            let page = match[1];

            const usernameMatch = url.match(constants.USERNAME_OBSCURE_REGEXP);
            if (usernameMatch) {
                // This regexp found a username in capture group 2,
                // so drop it, and join the prefix & suffix.
                page = usernameMatch[1] + '$USERNAME' + usernameMatch[3];
            }

            return { app: constants.SYSTEM_APP_NAME, page };
        }
        return null;
    }

    toJSON() {
        return {
            __type: 'Event',
            data: this.data,
            type: this._type,
            timestamp: this._timestamp,
            visibility: this.visibility,
            experienceID: this.experienceID,
            deploymentID: this.deploymentID,
            userID: this.userID,
            eventID: this.eventID,
        };
    }

    toPayload() {
        const result = {};
        result.component = `app.session.${this.type}`;
        result.data = this.data;
        result.timestamp = this.timestamp;
        result.visibility = this.visibility;
        result.experienceID = this.experienceID;
        result.deploymentID = this.deploymentID;
        result.userID = this.userID;
        result.eventID = this.eventID;
        return result;
    }

    get type() {
        return this._type;
    }


    get timestamp() {
        return this._timestamp;
    }

    /**
     * Checks all params of constructor if defined, else throw an error.
     * @param {object} eventData - Event data.
     * @param {string} deploymentID - ID of the Deployment.
     * @param {string} sessionId - ID of the Session.
     * @param {string} userID - ID of the current user.
     * @returns {boolean}
     * @private
     */
    _checkParams(eventData) {
        let errors = [];

        return errors.length === 0;
    }
    _generateExperienceID() {
        function seed() {
            return Math.floor((1 + Math.random()) * 0x10000)
              .toString(16)
              .substring(1);
        }
        return `${seed()}${seed()}-${seed()}-${seed()}-${seed()}-${seed()}${seed()}${seed()}`;
    }
}
