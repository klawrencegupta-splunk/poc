const routerUtils = require('util/router_utils');
const InstrumentationRouter =
    require('splunk_instrumentation/Instrumentation/routers/InstrumentationRouter');

// eslint-disable-next-line no-unused-vars
const router = new InstrumentationRouter();
routerUtils.start_backbone_history({ ignoreFragment: true });
