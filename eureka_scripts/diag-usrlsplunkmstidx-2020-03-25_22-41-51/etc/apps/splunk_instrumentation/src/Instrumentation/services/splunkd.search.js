var _ = require('underscore'),
    $ = require('jquery');

/**
 * The splunkd module will call this decorator function
 * with itself as the only argument.
 */
module.exports = function (splunkd) {

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
     *   + This object has a "results" property, otherwise that would have been the obvious name to use...
     * - getResults: fn (resultOptions) -> events. (Used for paging).
     */
    splunkd.search = function (query, opt) {
        opt = opt || {};

        var resolveData = {
            job: undefined,
            outcome: undefined,
            getResults: undefined
        };

        if (opt.owner || opt.user) {
            opt.makeUrl = _.bind(splunkd.servicesNsUrl, splunkd, opt.owner || '-', opt.app || '-');
        } else {
            opt.makeUrl = _.bind(splunkd.servicesUrl, splunkd);
        }

        return $.Deferred(function (deferred) {
            splunkd.search.start(query, opt).
                then(function (startResponse) {
                    return splunkd.search.wait(startResponse.sid, opt);
                }).
                then(function (job) {
                    resolveData.job = job;
                    return splunkd.search.getResults(job.entry[0].content.sid, opt);
                }).
                then(function (outcome) {
                    resolveData.outcome = outcome;
                    resolveData.getResults = constructGetResultsFunction(resolveData.job.entry[0].content.sid, opt);
                    resolveData.touch = constructTouchFunction(resolveData.job.entry[0].content.sid, opt);
                    deferred.resolve(resolveData);
                }).
                fail(function (err) {
                    deferred.reject(err);
                });
        });
    };

    /**
     * Starts a search job. The returned deferred will resolve with the xhr response.
     */
    splunkd.search.start = function (query, opt) {
        return splunkd.post(opt.makeUrl('search/jobs'), {}, _.defaults({
            search: query
        }, (opt && opt.search || {})))
    };

    /**
     * Waits for a seach job to complete, then resolves with the sid
     */
    splunkd.search.wait = function (sid, opt) {
        return $.Deferred(function (deferred) {
            var settled = false;
            var interval = setInterval(function () {

                splunkd.get(opt.makeUrl('search/jobs/' + sid)).then(function (job) {
                    if (settled) return;
                    if (job.entry[0].content.isDone) {
                        clearInterval(interval);
                        settled = true;
                        deferred.resolve(job);
                    }
                }).fail(function (reason) {
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
    splunkd.search.getResults = function (sid, opt) {
        return splunkd.get(
            opt.makeUrl('search/jobs/' + sid + '/results'),
            {},
            (opt && opt.results || {})
        );
    }
    
    function constructGetResultsFunction(sid, opt) {
        return function (resultOptions) {
            resultOptions.offset = resultOptions.offset || 0;
            resultOptions.count = resultOptions.count || 0;
            return splunkd.get(
                opt.makeUrl('search/jobs/' + sid + '/results'),
                {},
                _.extend({}, (opt && opt.results || {}), resultOptions)
            );
        };
    }
    
    function constructTouchFunction(sid, opt) {
        return function () {
            return splunkd.post(
                opt.makeUrl('search/jobs/' + sid + '/control'),
                {},
                _.extend({'action': 'touch'})
            );
        };
    }
};
