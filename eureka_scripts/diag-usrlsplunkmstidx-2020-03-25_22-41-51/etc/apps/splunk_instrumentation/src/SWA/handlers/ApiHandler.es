export default function ApiHandler(factory, options) {
    const queue = window._splunk_metrics_events;
    const push = function (item) {
        if (item.type === 'config')
            options.updateOptions(item.data);
        else
            factory(item);
    };

    window._splunk_metrics_events = { push };
    if (queue && queue.forEach) {
        queue.forEach(item => push(item));
    }
}

/**
 * plucks all the config event from the queue and updates swa._options
 * before swa starts processing events to allow developers to change the config.
 * @param options
 */

ApiHandler.init = function (options) {
    // if global does not exist or is not an array with reduce then do nothing.
    if (!window._splunk_metrics_events || !window._splunk_metrics_events.reduce) return;

    const newQueue = []
    const configs = window._splunk_metrics_events.reduce((accumulator, value)=> {
        if (value.type === 'config') {
            accumulator.push(value);
        } else {
            newQueue.push(value);
        }
        return accumulator;
    }, []);
    window._splunk_metrics_events = newQueue;

    configs.forEach((event) => options.updateOptions(event.data));
};
