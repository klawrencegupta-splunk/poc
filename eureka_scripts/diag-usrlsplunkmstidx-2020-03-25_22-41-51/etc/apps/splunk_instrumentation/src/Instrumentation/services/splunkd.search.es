const _ = require('underscore');
const $ = require('jquery');

/**
 * The splunkd module will call this decorator function
 * with itself as the only argument.
 */
module.exports = function splunkdDecorator(splunkd) {
    function constructGetResultsFunction(sid, opt) {
        return function (resultOptions) {
            const normalizedResultOptions = _.extend({
                offset: 0,
                count: 0,
            }, resultOptions);
            return splunkd.get(
                opt.makeUrl('search/jobs/' + sid + '/results'),
                {},
                _.extend({}, (opt && opt.results || {}), normalizedResultOptions)
            );
        };
    }

    function constructTouchFunction(sid, opt) {
        return function () {
            return splunkd.post(
                opt.makeUrl('search/jobs/' + sid + '/control'),
                {},
                _.extend({ 'action': 'touch' })
            );
        };
    }

    /**
     * Accepts an spl query, and returns a Deferred that will
     * resolve with the search results after the job completes.
     * If there are any http errors while waiting for the job
     * to complete or gathering results, the deferred will reject.
     *
     * If `opt` is supplied, it should be an object with these optional properties:
     * - search: An object containing parameters for the initial post to /search/jobs
     * - results: An object containing parameters for the get from /search/results
     *
     * Resolves with an object containing the following properties:
     * - job: The job object (result from posting to the search/jobs endpoint)
     * - outcome: The response from the search/jobs/SID/results endpoint.
     *   + This object has a "results" property, otherwise that would have been the
     *   obvious name to use...
     * - getResults: fn (resultOptions) -> events. (Used for paging).
     */
    splunkd.search = function search(query, opt = {}) {
        const options = _.extend({}, opt);
        const resolveData = {
            job: undefined,
            outcome: undefined,
            getResults: undefined,
        };

        if (options.owner || options.user) {
            options.makeUrl = _.bind(splunkd.servicesNsUrl, splunkd, options.owner || '-', options.app || '-');
        } else {
            options.makeUrl = _.bind(splunkd.servicesUrl, splunkd);
        }

        return new $.Deferred((deferred) => {
            splunkd.search.start(query, options).
                then((startResponse) => splunkd.search.wait(startResponse.sid, options)).
                then((job) => {
                    resolveData.job = job;
                    return splunkd.search.getResults(job.entry[0].content.sid, options);
                }).
                then((outcome) => {
                    resolveData.outcome = outcome;
                    resolveData.getResults = constructGetResultsFunction(
                        resolveData.job.entry[0].content.sid, options);
                    resolveData.touch = constructTouchFunction(
                        resolveData.job.entry[0].content.sid, options);
                    deferred.resolve(resolveData);
                }).
                fail((err) => {
                    deferred.reject(err);
                });
        });
    };

    /**
     * Starts a search job. The returned deferred will resolve with the xhr response.
     */
    splunkd.search.start = function start(query, opt) {
        return splunkd.post(opt.makeUrl('search/jobs'), {}, _.defaults({
            search: query,
        }, (opt && opt.search || {})));
    };

    /**
     * Waits for a seach job to complete, then resolves with the sid
     */
    splunkd.search.wait = function wait(sid, opt) {
        return new $.Deferred((deferred) => {
            let settled = false;
            const interval = setInterval(() => {

                splunkd.get(opt.makeUrl('search/jobs/' + sid)).then((job) => {
                    if (settled) return;
                    if (job.entry[0].content.isDone) {
                        clearInterval(interval);
                        settled = true;
                        deferred.resolve(job);
                    }
                }).fail((reason) => {
                    if (settled) return;
                    clearInterval(interval);
                    settled = true;
                    deferred.reject(reason);
                });

            }, 300);
        });
    };

    /**
     * Returns a deferred that will resolve to the results of the search.
     */
    splunkd.search.getResults = function getResults(sid, opt) {
        return splunkd.get(
            opt.makeUrl('search/jobs/' + sid + '/results'),
            {},
            (opt && opt.results || {})
        );
    };

};
