var router_utils = require('util/router_utils'),
    InstrumentationRouter = require('Instrumentation/routers/InstrumentationRouter');

var router = new InstrumentationRouter();
router_utils.start_backbone_history({ ignoreFragment:true });
