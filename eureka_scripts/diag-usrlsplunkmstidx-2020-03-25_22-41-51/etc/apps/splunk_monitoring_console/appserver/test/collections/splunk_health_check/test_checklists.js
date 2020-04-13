define([
    'jquery',
    'underscore',
    'collections/SplunkDsBase',
    'splunk_monitoring_console/collections/splunk_health_check/CheckLists'
  ], function(
      $,
      _,
      SplunkDsBaseCollection,
      CheckListsCollection
  ) {
    suite('setup', function() {
      setup(function() {
        this.collection = new CheckListsCollection();

        assert.ok(this.collection, 'collection should be created');

        sinon.stub(SplunkDsBaseCollection.prototype, 'fetch').returns($.Deferred());

        assert.ok(true, 'setup succeeded');
      });

      teardown(function() {
        this.collection = null;
        SplunkDsBaseCollection.prototype.fetch.restore();
        assert.ok(true, 'teardown succeeded');
      });

      test('fetch', function() {
        var defaultOptions = {
          'data': {
            'app': 'splunk_monitoring_console',
            'owner': '-'
          }
        };

        this.collection.fetch();
        assert.ok(SplunkDsBaseCollection.prototype.fetch.calledOnce, 'SplunkDsBaseCollection.prototype.fetch should be called once');
        //console.log('SplunkDsBaseCollection.prototype.fetch.getCall(0).args', SplunkDsBaseCollection.prototype.fetch.getCall(0).args);
        assert.ok(SplunkDsBaseCollection.prototype.fetch.calledWithExactly(defaultOptions), 'SplunkDsBaseCollection.prototype.fetch should be called with defaultOptions');
        assert.ok(SplunkDsBaseCollection.prototype.fetch.alwaysCalledOn(this.collection), 'SplunkDsBaseCollection.prototype.fetch should be called on this collection');

        SplunkDsBaseCollection.prototype.fetch.reset();
        var customOptions = {
          'count': 100,
          'sort_key': 'category'
        };
        var concatOptions = _.defaults({}, customOptions, defaultOptions);
        this.collection.fetch(customOptions);
        assert.ok(SplunkDsBaseCollection.prototype.fetch.calledOnce, 'SplunkDsBaseCollection.prototype.fetch should be called once');
        assert.ok(SplunkDsBaseCollection.prototype.fetch.calledWithExactly(concatOptions), 'SplunkDsBaseCollection.prototype.fetch. should be called with concatOptions');
      });
    });
  });