const API_VERSION = '1.0';

export default class Dispatcher {
    /** ***********************************************************************************************
     * PUBLIC API                                                                                    *
     *************************************************************************************************/
    /**
     * @param options - Pass in SWACore options to construct dispatcher
     */
    constructor(options) {
        this._options = options;
    }

    /**
     * Send data to CDS
     *
     * @param {Event[]} events - Array of Events to send
     * @param {boolean} final - Sends all data
     * @returns {Promise} Data sent or error
     */
    sendData(events = [{}], final = false) {
        const url = this._buildURL(events);
        const data = this.bundleData(events);
        this._options.log('Sending Data:', data);

        return new Promise((resolve, reject) => {
            if (url && data) {
                const onFail = function (status, text) {
                    reject({
                        status,
                        statusText: text,
                        events,
                    });
                };
                if (final && navigator.sendBeacon) {
                    // Uses sendBeacon because asynchronous POST will not work for window.unload.
                    const blob = new Blob([data], { type: 'application/json' });
                    if (navigator.sendBeacon(url, blob)) {
                        resolve({
                            response: 'success',
                            data,
                        });
                    }
                    else {
                        onFail(400, 'Error sending events.');
                    }
                }
                else {
                    const xhr = new XMLHttpRequest();
                    const headers = this._buildHeaders();

                    xhr.open('post', url);
                    xhr.onload = function () {
                        if (this.status >= 200 && this.status < 300) {
                            resolve({
                                response: xhr.response,
                                data,
                            });
                        }
                        else {
                            onFail(this.status, xhr.statusText);
                        }
                    };
                    xhr.onerror = function () {
                        onFail(this.status, xhr.statusText);
                    };
                    if (headers) {
                        Object.keys(headers).forEach(function (key) {
                            xhr.setRequestHeader(key, headers[key]);
                        });
                    }
                    try {
                        xhr.send(data);
                    } catch (e) {
                        onFail(0, e);
                    }
                }
            }
            else {
                const message = 'No Data Sent: URL not set.';
                reject(new Error(message));
            }
        });
    }

    /**
     * Formats data into JSON to be sent.
     * @param {Event[]} events - Array of Events to send
     * @returns {string|*} - JSON string of data.
     */
    bundleData(events = [{}]) {
        const bundleDataFunction = this._options.bundleDataFunction || 'json';
        if (bundleDataFunction instanceof Function) {
            return bundleDataFunction(events);
        } else if (bundleDataFunction === 'CDS') {
            return this._formatDataForCDS(events);
        } else if (bundleDataFunction === 'json') {
            return this._formatDataForEndpoint(events) 
        }
        return JSON.stringify(events);
    }

    /**
     * @returns {string} The API version.
     */
    getApiVersion() {
        return API_VERSION;
    }

    /** ***********************************************************************************************
     * PRIVATE FUNCTIONS                                                                             *
     *************************************************************************************************/
    /**
     * Builds URL according to CDS specs
     * @param {object} events
     * @returns {string} The URL
     * @private
     */
    _buildURL(events) {
        let baseURL = this._options['url'];

        if (baseURL && events && baseURL.indexOf('splkmobile') > -1) {
            let errorCount = 0;
            let eventCount = 0;

            (events || []).forEach((event) => {
                if (event.stacktrace || event.errorHash || event.klass) {
                    errorCount++;
                } else {
                    eventCount++;
                }
            });
            baseURL = [baseURL, this._options['MintUUID'], errorCount, eventCount].join('/');
        }
        return baseURL;
    }

    /**
     * Builds the headers to send to CDS
     * @param {boolean} sendToHEC
     * @returns {Object} Headers
     * @private
     */
    _buildHeaders(sendToHEC = this._options['sendToHEC']) {
        const headers = {};

        // Setting different headers
        if (sendToHEC) {
            headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8';
            headers['Authorization'] = 'Splunk '.concat(this._options['token']);
        }
        else {
            headers['Content-Type'] = 'application/json;charset=UTF-8';
            headers['X-Splunk-Mint-Send-CORS'] = true;
        }
        return headers;
    }
    

    /**
     * Formats data to be sent to Internal Rest Endpoint
     * @param events
     * @returns {object}
     * @private
     */
    _formatDataForEndpoint(events) {
        return JSON.stringify(events.map((event) => {
            return event.toPayload();
        }))
    }
    /**
     * Formats data to be sent to CDS
     * @param events
     * @returns {string|*}
     * @private
     */
    _formatDataForCDS(events) {
        return events.map((event) => {
            const result = event.toPayload();
            result.version = this._options['version']
            const root = {
                sdkVersion: '4.3',
                osVersion: '0',
                event_name: 'Deployment',
                appVersionCode: '3',
                uuid: this._options.deploymentID,
                packageName: 'splunk_instrumentation',
                extraData: result,
                session_id: result.experienceID,
                appVersionName: '1',
            };

            return JSON.stringify(root) + ['{', parseInt(this.getApiVersion()), 'event', event.timestamp].join('^') + '}';
        }).join('');
    }
}
