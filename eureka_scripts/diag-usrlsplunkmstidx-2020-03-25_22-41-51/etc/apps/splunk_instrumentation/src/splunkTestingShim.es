window.jqueryDefferedTest = function (fn) {
    return function testWrapper(done) {
        fn().fail(done).done(() => { done(); });
    };
};
