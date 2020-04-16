var config = {
    baseUrl: $C.MRSPARKLE_ROOT_PATH + "/" + $C.LOCALE + "/static/js",
    //wrapShim: true,
    shim: {
        bootstrap: {
            deps: ['jquery']
        },
        'bootstrap_table': {
            deps: ['jquery']
        },
        'bootstrapValidator': {
            deps: ['jquery']
        }
    },
    paths: {
        'app': '../app/Splunk_TA_f5-bigip/js',
        'lib': '../app/Splunk_TA_f5-bigip/js/lib',
        'coreStatic': '../../static/js',
        'bootstrap': '../app/Splunk_TA_f5-bigip/bootstrap/js/bootstrap.min',
        'bootstrap_table': '../app/Splunk_TA_f5-bigip/bootstrap-table/bootstrap-table.min',
        'bootstrapValidator': '../app/Splunk_TA_f5-bigip/jqBootstrapValidation/jqBootstrapValidation'
    },
    enforceDefine: false
};

require.config(config);
