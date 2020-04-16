var _ = require('underscore'),
    $ = require('jquery'),
    Backbone = require('backbone'),
    BaseView = require('views/Base'),
    VolatileExpression = require('./VolatileExpression');

var count = function () {};
// var count = console.count.bind(console);

var log = function () {};
// var log = function () { console.log.apply(console, arguments); };

/**
 * Components are Views with automatic rendering and lifecycle management.
 *
 * A Component...
 *
 * - Does its own rendering.
 *   + You do not have to write a `render` method.
 *   + IMPORTANT: This assumes you're using the Model & Collection classes from this "framework."
 * - Automatically listens for change events and re-renders as appropriate.
 *   + Any Model's attribute or Collection contents that is accessed in the
 *     template is registered as a dependency of the view. When it changes,
 *     a render is queued for that view automatically.
 * - Only renders itself, child views will render themselves when needed.
 * - Automatically manages child view lifecycles.
 *   + You provide factory functions to construct child views. Like templates,
 *     any Model attributes or Collection contents accessed in the factory is
 *     made a dependency of that child views identity. When a change is detected,
 *     the child view is reconstructed. If no change has happened, the child
 *     view is reused throughout its parent's render cycles.
 * - Renders asynchronously.
 *   + When a change happens in the view, a render is queued. All queued renders
 *     are performed at once in top-down order at about 20-fps. The throttled, top-down
 *     approach elimates extra renders in a few ways:
 *     - If the model for a view changes multiple times between render cycles, only
 *       a single render is performed to reflect both changes.
 *     - If a member of a collection was changed, but later removed from the collection,
 *       we avoid rendering the child entirely as the parent is rendered first and removes
 *       the child from the DOM & the render queue.
 *
 * Example:
 *
 *     // Shows a HeaderComponent & a list of ItemComponents.
 *     // If the headerModel or collection of items changes, the component
 *     // Will automatically update it's view.
 *     // NOTE: The data-component & data-component-id attributes map to
 *     //       the child component factories in the `components` hash.
 *     //       When rendered, these elements are replaced by the root $el
 *     //       of the child component that was created to fill that spot.
 *
 *     MyComponent = Component.extend({
 *       template: '<div data-component="headerComponent"></div>' +
 *                 '<% _.each(collection, function (item, index) {' +
 *                 '  <div data-component="itemComponent" data-component-id="<%= index %>"></div>' +
 *                 '<% }) %>',
 *       templateContext: function () {
 *          return { model: this.model, collection: this.collection };
 *       },
 *       components: {
 *         headerComponent: function () {
 *           return new HeaderComponent({ model: this.model.get('headerModel') });
 *         },
 *         itemComponent: function (index) {
 *           return new ItemComponent({ model: this.collection.at(index) });
 *         }
 *       }
 *     });
 *
 */
var _super = BaseView;
var Component = _super.extend({

    // Public Stuff
    // ------------

    // Your subclass will probably want to override the defaults found here:

    /**
     * Overridden by subclasses as a hash of component names to factory
     * functions. The function may take a single string parameter, a component ID,
     * to use when constructing the Component.
     *
     * Once the view is bound (which happens on the first call to `render`),
     * these factories are used to create child elements as needed. For more
     * details on child view lifecycle management, see the `cycleChildComponents`
     * method.
     */
    components: {},

    /**
     * Template is empty by default. Useful if you do all your DOM
     * manipluations manually (as in the ComponentAdapter).
     */
    template: '',

    /**
     * Derives the argument to the compiled template when rendering.
     * By default returns this (the view itself).
     */
    templateContext: function () {
        return this;
    },

    /**
     * Component lifecycle hooks.
     * (You could also listen to 'beforeRender' & 'afterRender' events.)
     */
     beforeFirstRender: function () {},
     beforeRender: function () {},
     afterRender: function () {},

    // Internals
    // ---------

    // Not saying you'll never need to, but at the moment nothing below has
    // been *designed* to be overridden by children. If you need to provide
    // a hook into one of these methods, you'll want to think like, super
    // hard about it first.

    /**
     * initialize this component.
     */
    initialize: function (opt) {
        var options = opt || {};

        _super.prototype.initialize.apply(this, arguments);

        // Allow overriding template, templateContext, etc., in constructor
        // for making simple inline components.
        if (options.template) this.template = options.template;
        if (options.templateContext) this.templateContext = options.templateContext;
        if (options.components) this.components = options.components;

        this.__didFirstRender__ = false;
        this.__didBindTemplate__ = false;
        this.__didShutdown__ = false;

        // Do we need to re-render the template?
        this.__needsTemplateRendered__ = true;

        // Do we need to cycle the children?
        this.__needsChildrenCycled__ = true;

        // Did we queue a render for this animation frame?
        this.__isRenderPending__ = false;

        // An index of known child components. Used to memoize the factory functions
        // in the `components` hash by the factory name & view ID. Not set on
        // the prototype on purpose. (Don't want multiple views sharing a cache of children).
        this.__childComponents__ = {};

        this.on('beforeRender', this.notifyBeforeRender.bind(this));
        this.on('afterRender', this.afterRender.bind(this));
    },

    notifyBeforeRender: function () {
        if (!this.__didFirstRender__) this.beforeFirstRender();
        this.beforeRender();
    },

    /**
     * Ensures `shutdown` is called during the removal process.
     */
    remove: function () {
        this.shutdown();
        return Backbone.View.prototype.remove.apply(this, arguments);
    },

    /**
     * First invocation binds the template, which automatically creates change listeners
     * to re-render when any underlying models change.
     *
     * Subsequest invocations will render the template for this component, then
     * run the child component lifecycle management method, `cycleChildComponents`.
     *
     * Note the first invocation is indirectly self recursive, so all child
     * views will be rendered and mounted in the DOM for this view immediately.
     *
     * THROTTLING: Ordinarily render is throttled such that it takes no action
     * until the next render frame (see the static Component.queueRender function below
     * for details). If you want the view to render immediately, say so:
     *
     *     view.render({immediate: true});
     */
    render: function (opt) {
        opt = opt || {};

        // May have queued a render before getting removed from the DOM
        // (and therefore set our own __didShutdown__ flag). If so, just
        // ignore this call. We'll be removed from the render queue and free
        // for GC (assuming no dangling references in client code).
        if (this.__didShutdown__) return;

        if (!this.__didBindTemplate__) {
            this.bindTemplate();
            this.render(opt);
        } else if (!this.__didFirstRender__ || opt.immediate) {
            this.trigger('beforeRender');
            this.__didFirstRender__ = true;
            this.__isRenderPending__ = false;

            count('rendering => ' + this.name);

            if (this.__needsTemplateRendered__) {
                // count('renderTemplate => ' + this.name);
                this.renderTemplate();
            }
            if (this.__needsChildrenCycled__) {
                // count('cycleChildComponents => ' + this.name);
                this.cycleChildComponents();
            }
            this.trigger('afterRender');
        } else {
            this.queueRender();
        }
        return this;
    },

    /**
     * Queue up a render on the next render frame.
     * (Idempotent between render cycles.)
     */
    queueRender: function () {
        if (!this.__isRenderPending__) {
            this.__isRenderPending__ = true;
            // Call static queueRender method
            Component.queueRender(this);
        }
    },

    // Indicates depth in the tree. Lower numbers are rendered first.
    // In that way, we avoid rendering a child view with a change if
    // a render of the parent would have removed it immediately after
    // anyway.
    renderPriority: function () {
        if (this.parent) {
            return 1 + this.parent.renderPriority();
        } else {
            return 0
        }
    },

    /**
     * Compiles the template into a VolatileExpression, which provides automatic
     * change detection for the underlying models. These change events are then
     * watched to efficiently re-render only when required, and at a throttled pace.
     * (Ideally we would throttle with something like requestAnimationFrame, but
     * here I'm just debouncing for simplicitly. It has a similar effect.)
     */
    bindTemplate: function () {
        this.__didBindTemplate__ = true;
        this.__compiledTemplate__ = this.__compiledTemplate__ || _.template(this.template);

        // Clean any previous template expression (removes event listeners).
        if (this.__templateExpr__) {
            this.__templateExpr__.dispose();
            this.stopListening(this.__templateExpr__);
        }

        // "VolatileExpression" automatically binds change listeners to all model attributes
        // that are `model.get(...)`-ed when the given function runs (so, while rendering the template).
        this.__templateExpr__ = new VolatileExpression(function () {
            return this.__compiledTemplate__(this.templateContext());
        }.bind(this));

        // Once a change is detected, the VolatileExpression triggers the `change` event, then
        // immediately stops listening for changes until it is re-evaluated (which happens on render).
        this.listenTo(this.__templateExpr__, 'change', function () {
            this.__needsTemplateRendered__ = true;
            this.queueRender();
        }.bind(this));

        this.queueRender();
    },

    /**
     * Renders the compiled template into `this.$el`. The `templateContext`
     * method, which is intended to be overridden by subclasses, is invoked
     * to determine the context argument to the template.
     */
    renderTemplate: function () {
        this.__needsTemplateRendered__ = false;
        this.__needsChildrenCycled__ = true;

        this.$el.html(this.__templateExpr__.evaluate());
        this.$ownElements = this.$('*');

        this.eachChildComponent(function (child) {
            child.__isMounted__ = false;
        });
    },

    /**
     * Run a single iteration of the child lifecycle management logic.
     * Designed to be called after `renderTemplate` to re-parent the child
     * components in the newly created DOM & ensure all event handlers are
     * correctly reset.
     *
     * - Child views are created as needed according to the `data-component*` attributes.
     *   Their place in the DOM is found by the attribute tuple (data-component, data-component-id)
     *   + `data-component` reffers to a component factory function on `this.components`.
     *   + `data-component-id` is the argument to the factory function (called viewID by convention).
     *
     * - Child views are re-used between render cycles if possible.
     *
     * - Components that are no longer used, because the (data-component, data-component-id)
     *   tuple they were created for is no longer in the rendered template,
     *   are removed and dereferenced.
     */
    cycleChildComponents: function (renderedTemplate) {
        // Child Components...

        this.__needsChildrenCycled__ = false;

        // Mark each memoized view as __garbage__.
        // If the view is already marked __stale__, remove it immediately.
        this.eachChildComponent(function (child, factoryName, viewID) {
            if (child.__stale__) {
                // Move the child to a new element before removing so we
                // don't lose the child root (which is part of our template).

                // Detach the node, keeping the root element in our DOM
                // as a queue to recreate the child in the next step.
                Component.prototype.detachFromRoot.call(child);

                // Now that the view is detached from the root,
                // we can safely remove it.
                this.removeChild(child, factoryName, viewID);
            } else {
                child.__garbage__ = true;
            }
        }.bind(this));

        // For each child view root element found in the DOM,
        // fetch the child view, and unset it's __garbage__ flag.
        this.$ownElements.filter('[data-component]').each(function (i, childRoot) {
            var $parent = $(childRoot),
                factoryName = $parent.attr('data-component'),
                viewID = $parent.attr('data-component-id');

            var child = this.childComponent(factoryName, viewID);

            if (!child) {
                throw new Error('Expected to always find/create a child here...');
            }

            child.__garbage__ = false;

            if (!child.__isMounted__) {
                child.replace($parent);
                child.__isMounted__ = true;
            }

            // ---------- HACK for SPL-127721. TODO Find fix for component lifecycle in IE 11  ----------
            if (child.name && child.__templateExpr__ && child.name.indexOf('DateRangeSelector') != -1) {
              child.renderTemplate();
            }
        }.bind(this));

        // Now that child views have been re-parented/created anew,
        // remove any that are no longer used.
        this.eachChildComponent(function (child, factoryName, viewID) {
            if (child.__garbage__ === true) {
                this.removeChild(child, factoryName, viewID);
            }
        }.bind(this));
    },

    /**
     * Remove a child view from the DOM and this view's memoization cache.
     * (Should only be called by the base Component class. For child views that
     *  are managed manually, you would just remove them directly yourself.)
     */
    removeChild: function (child, factoryName, viewID) {
        count('removing ' + (child.__stale__ ? 'stale ' : '') + (child.__garbage__ ? 'garbage ': '') + '=> ' + child.name);
        child.remove();
        delete this.__childComponents__[factoryName][viewID];
    },

    detachFromRoot: function () {
        var $detachedRoot = this.el.cloneNode();
        this.$('> *').appendTo($detachedRoot);
        this.$el.empty();
        this.setElement($detachedRoot);
    },

    /**
     * Iterates over all child components.
     */
    eachChildComponent: function (callback) {
        Object.keys(this.__childComponents__).forEach(function (factoryName) {
            var factoryCache = this.__childComponents__[factoryName];
            if (factoryCache) {
                Object.keys(factoryCache).forEach(function (viewID) {
                    var child = factoryCache[viewID];
                    if (!child) {
                        delete factoryCache[viewID];
                    } else {
                        callback(child, factoryName, viewID);
                    }
                }.bind(this));
            }
        }.bind(this));
    },

    /**
     * Memoized child component lookup.
     * - `factoryName` corresponds to a key on `this.components`
     * - `viewID` is the argument passed to the factory function if a new
     *   view must be created to fulfill the request.
     */
    childComponent: function (factoryName, viewID) {
        // Check for memoized view...
        // - viewID can be `undefined`, that's ok. (Just means the factory only makes a single view)
        var memoized = this.__childComponents__[factoryName] && this.__childComponents__[factoryName][viewID];

        if (memoized) {
            count('reusing => ' + memoized.name);
            return memoized;
        } else {
            // Double-assignments are used to reduce hash lookups.
            // (These objects may have members `delete`-ed over time,
            //  so their member access may be de-optimized. This helps
            //  to reduce any peformance impact.)
            var factoryCache = this.__childComponents__[factoryName];
            if (!factoryCache) {
                this.__childComponents__[factoryName] = factoryCache = {};
            }

            var child = factoryCache[viewID] = this.createChildComponent(factoryName, viewID);
            return child;
        }
    },

    /**
     *  SHOULD ONLY BE CALLED BY `this.childComponent` !!!!
     * Create a child component to fulfill the given factoryName & viewID.
     * Uses the `this.components` hash to look up a generator function and
     * calls it to create the child component. The result is memoized. If
     * the generator expression changes, marks the view as `__stale__` and
     * queues a render. When the render executes the view will be replaced.
     */
    createChildComponent: function (factoryName, viewID) {
        if (!this.components[factoryName]) {
            throw new Error('No component factory named ' + factoryName + '.');
        }

        // Create a VolatileExpression from the child view factory.
       var factoryExpression = new VolatileExpression(function () {
           return this.components[factoryName].call((this.componentsContext ? this.componentsContext : this ), viewID);
       }.bind(this));

       var newComponent = factoryExpression.evaluate();
        newComponent.parent = this;

        count('creating => ' + newComponent.name);

        // If the expression for this view receives a change event,
        // mark it dirty and queue up a render.
       factoryExpression.on('change', function () {
           var factoryCache = this.__childComponents__[factoryName],
               memoizedComponent = factoryCache && factoryCache[viewID];

           if (memoizedComponent) {
               memoizedComponent.__stale__ = true;
               this.__needsChildrenCycled__ = true;
               this.queueRender();
           } else {
               throw new Error('Expected to find a memoized view here...');
           }

           factoryExpression.dispose();
       }.bind(this));

        // Duck typing components vs. legacy views
        if (newComponent.queueRender) {
            newComponent.queueRender();
        } else {
            newComponent.render();
        }

        // Since we'll be replacing the placeholder element in the parent
        // with the new child component's element, make sure we preserve
        // the data-component attributes.
        newComponent.$el.attr('data-component', factoryName);
        newComponent.$el.attr('data-component-id', viewID);

        this.__childComponents__[factoryName] = this.__childComponents__[factoryName] || {};
        this.__childComponents__[factoryName][viewID] = newComponent;

        return newComponent;
    },

    /**
     * Move a view to a new root element.
     * - Calls `$(el).empty` on the new root, so any existing children (including text) are removed.
     * - Delegates events & relocates the inner DOM nodes.
     * - All attributes on the new root element are removed, and replaced with the attributes
     *   from the previous root element. (So it's the same as it was, just moved).
     *
     * Pre-condition: Component to move has all content in child elements
     *                (i.e. no text at the root level). If you have text
     *                in your root element, just wrap it in a div/span.
     *
     * TODO: Usage of `move` has been replaced by `detachFromRoot` & `replace`.
     *       This method may be removed. (Replace does not have the pre-condition restriction
     *       and requires less work. `detachFromRoot` is also much faster for its purpose.)
     */
    move: function (newParent) {
        // Coerce $newParent into a jquery object &
        // newParent into a raw dom element.
        var $newParent = $(newParent);
        newParent = $newParent.get(0);

        var dom = this.$('> *');
        $newParent.empty();
        dom.appendTo(newParent);

        _.chain(newParent.attributes)
            .map(function (attr) { return attr.name; })
            .each(function (attrName) {
                $newParent.removeAttr(attrName);
            });
        _.each(this.el.attributes, function (attr) {
            $newParent.attr(attr.name, attr.value);
        }.bind(this));

        this.setElement(newParent);
    },

    /**
     * Replace the given element with this view.
     */
    replace: function (elementToReplace) {
        var $elementToReplace = $(elementToReplace);
        $elementToReplace.replaceWith(this.$el);
        this.setElement(this.$el); // TODO: Should just be a delegateEvents call, eh?
    },

    /**
     * Shut this view down. Stop listening to everything. Don't render again.
     */
    shutdown: function () {
        this.stopListening();
        this.eachChildComponent(function (child, factoryName, viewID) {
            this.removeChild(child, factoryName, viewID);
        }.bind(this));
        if (this.__templateExpr__) {
            this.__templateExpr__.dispose();
            this.__templateExpr__ = null;
        }
        this.__didShutdown__ = true;
    }
}, {

    // Render Queue Management
    // -----------------------

    // Renders are queued by default. If renders are pending, there is a single
    // timeout set. When the timeout is triggered, all queued views are rendered,
    // in a breadth-first traversal (top-down from every root component).

    renderQueue: [],

    queueRender: function (view) {
        // If we're not already expecting to render soon, setup a new timer.
        // Otherwise, we can just keep waiting for the next render frame.
        if (!this.renderTimeout) {
            this.renderTimeout = setTimeout(function () {
                log('=== PRIMARY RENDER @ ' + (new Date().getTime()) + ' ===');
                this.render();
                while (this.renderQueue.length > 0) {
                    log('-- secondary render --');
                    this.render();
                }
                this.renderTimeout = null;
            }.bind(this), 50);
        }
        this.renderQueue.push(view);
    },

    render: function () {
        this.trigger('beforeRender');

        var priorityQueue = {};

        if (!(this.renderQueue.length > 0)) return;

        // In case some misbehaved view queues another render during this
        // cycle of rendering, we go ahead and re-initialize the renderQueue,
        // saving off it's value to iterate over.
        var activeRenderQueue = this.renderQueue;
        this.renderQueue = [];

        activeRenderQueue.forEach(function (view) {
            var priority = view.renderPriority(),
                queue = priorityQueue[priority];

            if (!queue) {
                queue = priorityQueue[priority] = [];
            }
            queue.push(view);
        });

        log('Render Priority Queue: ', priorityQueue);
        _(Object.keys(priorityQueue))
            .map(function (n) { return parseInt(n, 10); })
            .sort()
            .forEach(function (priority) {
                priorityQueue[priority].forEach(function (view) {
                    view.render({immediate: true});
                });
            });

        this.trigger('afterRender');
    },

    renderTimeout: null
});

_.extend(Component, Backbone.Events);

module.exports = Component;
