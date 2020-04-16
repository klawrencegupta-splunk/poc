# appserver/

## Routes

### Controller Routes

Controllers are exposed as an endpoint in `web.conf`. The routes defined on the controller
are exposed at `http://$HOST:$PORT/custom/<APP_NAME>/<PYTHON_NODULE_NAME>/<METHOD_NAME>`.

In this case: `http://$HOST:$PORT/custom/splunkwebcore_spa/swc_controller/index`

See "Implementing Controllers" below for details on... implementing controllers.

### Static Files

Static files live in `$SPLUNK_HOME/etc/apps/$APP_NAME/appserver/static` and can be accessed at
`http://$HOST:$PORT/$LOCALE/static/app/$APP_NAME/$FILE`.

For example: `http://localhost:8000/en-US/static/app/splunk_instrumentation/index.html`

## Implementing Controllers

You'll want to import the following modules:

```Python
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
```

Your controller should inherit from `controllers.BaseController`.

Any methods that are to be exposed as routes should be decorated with `@expose_page(must_login=[True|False])`.
`@expose_page` is described in more detail in the comments in the `splunk.appserver.mrsparkle.lib.decorators` module.

If your route takes parameters, you'll want to define the route format with `@route(route='/:your/:route/*format', methods='GET')`.
`@route` is described in more detail in the comments in the `splunk.appserver.mrsparkle.lib.routes` module.
