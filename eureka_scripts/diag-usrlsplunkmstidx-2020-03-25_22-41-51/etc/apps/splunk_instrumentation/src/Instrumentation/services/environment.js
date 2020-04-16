var Model = require('Instrumentation/framework/Model');

/**
 * This model is populated by the router before constructing any views.
 * Later, this model is accessed by views (or other components) without
 * having to have the contents explicitly injected (possibly through a
 * deep tree of parent modules), or having to wait on the deferreds provided
 * by the base router.
 */
module.exports = new Model({
    // Set to the ApplicationModel from BaseRouter.model.application
    application: undefined,

    // Set to the UserModel from BaseRouter.model.application
    user: undefined,

    // Set to the router instance by the router itself
    router: undefined
});
