import Event from 'splunk_instrumentation/SWA/models/Event';

export default class EventQueue {
    /*************************************************************************************************
     * PUBLIC API                                                                                    *
     *************************************************************************************************/
    /**
     * @param options - Pass in SWACore options to construct event queue
     * @param dispatcher - Pass in dispatcher to send events from queue
     */
    constructor(options, dispatcher) {
        this._options = options;
        this._dispatcher = dispatcher;
        this.factory = this.push.bind(this);
        this._events = [];
    }

    /**
     * Adds data into queue. Once queue reaches QUEUE_SIZE, it will send data.
     *
     * all events should format is  { type,  data ,timestamp, date}
     *
     * @param {string} eventType - The type of event.
     * @param {Object} event - Data to push to queue.
     */
    push(pevent) {
        let response;
        const event = this._createEvent(pevent);

        if (event && (event.type === 'final' || event.type === 'unload' || event.type === 'flush')) {
            response = this.flush(event.type);
        } else if (event && event.type === 'save') {

            this._options.eventRecovery(this._events);
        } else {
            this._options.log('Pushing Data To Queue:', event);
            this._events.push(event);
            if (this.getQueueSize() >= this._options.maxQueueSize) {
                response = this._send(this._events);
                this._emptyQueue();
            } else {
                response = Promise.resolve();
            }
        }
        this._options.log('Current Queue:', this._events);
        return response;
    }

    /**
     * Flush out queue and sends all data.
     * @param {string} flush - Type of flush: 'flush' or 'unload'
     */
    flush(flush) {
        let response;
        this._options.log('Flushing Queue (' + flush + '):', this._events);

        if (this.getQueueSize() > 0) {
            if (flush === 'flush') {
                response = this._send(this._events);
            }
            //For unload, dispatch remaining data using sendBeacon method
            else if (flush === 'final' || flush === 'unload') {
                response = this._send(this._events, true);
            }
            this._emptyQueue();
        } else {
            response = Promise.resolve();
        }

        return response;
    }

    /**
     * @returns {*|Number} Size of the queue
     */
    getQueueSize() {
        return this._events.length;
    }

    /************************************************************************************
     * PRIVATE FUNCTIONS                                                                *
     ***********************************************************************************/
    _createEvent(pevent) {
        let event = (typeof pevent === 'string') ? {type: pevent} : pevent;
        if (!event) {
            event = {
                type: 'event',
            };
        }
        return new Event(event, this._options.experienceID,
            this._options.userID, this._options.deploymentID);
    }

    /**
     * Sends data to dispatcher.
     * @param {Object} data - Data to send.
     * @private
     */
    _send(data, final = false) {
        return this._dispatcher.sendData(data, final)
            .catch((error) => this._options.eventRecovery(error.events));
    }

    /**
     * Empties the queue.
     * @private
     */
    _emptyQueue() {
        this._events = [];
    }
}
