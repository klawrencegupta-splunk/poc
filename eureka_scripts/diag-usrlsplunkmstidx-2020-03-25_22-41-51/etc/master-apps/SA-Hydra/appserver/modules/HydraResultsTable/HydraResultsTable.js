Splunk.Module.HydraResultsTable = $.klass(Splunk.Module.SimpleResultsTable, {
	initialize : function($super, container) {
		// call the orginal
		$super(container);
		// set up our hide cells as false at first, and set
		// the idx adjustment
		this.hideSelector = false;
		this.idxAdjustment = Splunk.util
				.normalizeBoolean(this
						.getParam("displayRowNumbers")) ? 2
				: 1;
	},
	getResultURL: function(params) {
		var uri = Splunk.util.make_url('module', Splunk.util.getConfigValue('SYSTEM_NAMESPACE'), "SimpleResultsTable", 'render');
		params = params || {};
		if (!params.hasOwnProperty('client_app')) {
			params['client_app'] = Splunk.util.getCurrentApp();
		}
		uri += '?' + Splunk.util.propToQueryString(params);
		return uri;
	},
	renderResults : function($super, htmlFragment) {
		var tmpFields = [];
		var idxadj = this.idxAdjustment;
		$("span.sortLabel", htmlFragment).each(
				function(idx) {
					var field = $(this).text();
					if (field.slice(0, 5) === "HIDE-") {
						// The adjustment is because of
						// simple results table's
						// everpresent elements/selector
						// details
						tmpFields.push(idx + idxadj);
					}
				});
		var selectorTemplate = "td:nth-child($idx$),th:nth-child($idx$)";
		this.hideSelector = [];
		var re = new RegExp("\\$idx\\$", "g");
		for ( var ii = 0; ii < tmpFields.length; ii++) {
			this.hideSelector.push(selectorTemplate
					.replace(re, tmpFields[ii]));
		}

		// call the orginal
		$super(htmlFragment);
		// hide the unclean!
		for (ii = 0; ii < this.hideSelector.length; ii++) {
			$(this.hideSelector[ii], this.container).hide();
		}
	},
	// Overload for highlight issues in custom template
	getElementToHighlight : function(el) {
		if (!$(el).parent().length)
			return false;

		if ($(el).hasClass('pos'))
			return false;

		// if this is a multivalue field and you're over the
		// TD instead of over a value, we bail..
		if (el.tagName == 'TD'
				&& $(el).find("div.mv").length > 0)
			return false;
		// This is the patch, use a descendent selector to
		// get only row elements that are descendents of the
		// container div
		var row = $(el)
				.parents("#" + this.moduleId + " tr");

		switch (this.drilldown) {
		case "all":
			return $(row); // all is all row elements! not
							// 1 element!
		case "row":
			return $(row);
		default:
			// drilldown configuration takes precedence.
			// only after we've given them a chance does
			// this take effect.
			if (this.getInferredEntityName() == "events") {
				return $(el);
			}
		}
		return false;
	},
	onRowMouseover : function(evt) {
		if ($(evt.target).is(
				'.empty_results, .resultStatusHelp a'))
			return false;
		if (this.drilldown == 'none'
				&& this.getInferredEntityName() != "events")
			return false;

		var toHighlight = this
				.getElementToHighlight(evt.target);
		if (toHighlight) {
			toHighlight.addClass('mouseoverHighlight');
			// All of this was rather silly, it messes with
			// pages that use a custom template that
			// involves tables.
			// if (this.drilldown == "all") {
			// // I'd really like to just take the existing
			// jquery collection in toHighlight and merge it
			// with
			// // these two other jquery objects, and do it
			// all within 'getElementToHighlight' even
			// // however $().add() needs to do it all
			// within one monolithic xpaths which is weak.
			// //this.getRowFieldCell(toHighlight).addClass('mouseoverHighlight');
			// //var coordinates =
			// this.getXYCoordinates(toHighlight);
			// //this.getColumnFieldCell(coordinates.x,
			// toHighlight).addClass('mouseoverHighlight');
			// }
		}
	},
	onRowMouseout : function(evt) {
		if ($(evt.target).is(
				'.empty_results, .resultStatusHelp a'))
			return false;
		if (this.drilldown == 'none'
				&& this.getInferredEntityName() != "events")
			return false;

		var toHighlight = this
				.getElementToHighlight(evt.target);
		if (toHighlight.length > 0) {
			toHighlight.removeClass('mouseoverHighlight');
			if (this.drilldown == "all") {
				this.getRowFieldCell(toHighlight)
						.removeClass('mouseoverHighlight');
				var coordinates = this
						.getXYCoordinates(toHighlight);
				this.getColumnFieldCell(coordinates.x,
						toHighlight).removeClass(
						'mouseoverHighlight');
			}
		}
	},
	// Overload for better click vars on drilldown all
	getSelectionState : function(evt) {
		var el = $(evt.target);
		var coordinates = this.getXYCoordinates(el);
		var selection = {};
		var rowCell;

		if (this.drilldown == "none") {
			return false;
		} else if (this.drilldown == "all") {
			// if this is configured to do cell click, but
			// the cell in particular is not marked as
			// clickable.

			if (!el.hasClass('d')
					&& !el.parent().hasClass('d')) {
				return;
			}

			// Set all fields for the row into the selection
			var $tr = $(el).parents(
					"#" + this.moduleId + " tr");
			$("td", $tr)
					.each(
							function() {
								var $this = $(this);
								if ($this.attr("field")) {
									selection[$this
											.attr("field")] = $this
											.text();
								}
							});

			selection.element = el;
			selection.name = this.getRowFieldName(el);
			selection.value = this.getRowFieldValue(el);

			selection.name2 = this.getColumnName(
					coordinates.x, el);
			selection.value2 = el.text();

		} else if (this.drilldown == "row") {
			rowCell = $($(el).parents("tr")[0]);
			selection.element = rowCell;
			selection.name = Splunk.util.trim($(
					el.parents("table.simpleResultsTable")
							.find("th:not('.pos')")[0])
					.text());
			selection.value = this.getRowFieldValue(el);
			// for row clicks the second pair is the same,
			// but we send it anyway.
			// as far as what information we send
			// downstream, this is EXACTLY as though we were
			// in drilldown='all' and the user actually
			// clicked on the first column.
			selection.name2 = selection.name;
			selection.value2 = selection.value;
		}

		selection.modifierKey = this
				.getNormalizedCtrlKey(evt);

		if (selection.name == "_time") {
			rowCell = this.getRowFieldCell(el);
			selection.timeRange = this
					.getTimeRangeFromCell(rowCell);
		}

		// temporary fix for SPL-27829. For more details see
		// comment in FlashChart.js,
		// on FlashChart.stripUnderscoreFieldPrefix();
		if (selection.name2
				&& selection.name2
						.indexOf(this.LEADING_UNDERSCORE_PREFIX) != -1) {
			selection.name2 = selection.name2.replace(
					this.LEADING_UNDERSCORE_PREFIX, "_");
		}
		return selection;
	}
});

