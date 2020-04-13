Splunk.Module.HydraNodeAdder = $.klass(Splunk.Module, {
	initialize: function($super, container) {
		$super(container);
		//Set up internal variables
		this.app = this.getParam("app");
		this.gate_key = this.getParam("gate_key", false);
		var $hydra_node_dialog = $(".hydra-node-dialog", this.container);
		var $hydra_node_tips = $("p.validate-tips", this.container);
		var that = this;
		this.$hydra_node_tips = $hydra_node_tips;
		this.$hydra_node_dialog = $hydra_node_dialog;
		
		//Set up the dialog
		var updateTips = function(t, $tips) {
			$tips
				.text( t )
				.addClass( "ui-state-highlight" );
			setTimeout(function() {
				$tips.removeClass( "ui-state-highlight", 1500 );
			}, 500 );
		};
		var checkRegexp = function( o, regexp, n, $tips) {
			if ( !( regexp.test( o.val() ) ) ) {
				o.addClass( "ui-state-error" );
				updateTips(n, $tips);
				return false;
			} else {
				return true;
			}
		};
		$hydra_node_dialog.dialog({
			autoOpen: false,
			dialogClass: "conf-dialog",
			height: 320,
			width: 420,
			modal: true,
			buttons: {
				Cancel: {
					class: 'left-button',
					text: 'Cancel',
					click: function() {
						$(".dialog-field", $hydra_node_dialog).removeClass( "ui-state-error" );
						$( this ).dialog( "close" );
					}
				},
				"Save": {
					class: 'right-button',
					text: 'Save',
					click: function() {
						var validation = true;
						$(".dialog-field", $hydra_node_dialog).removeClass( "ui-state-error" );
						
						validation = validation && checkRegexp( $('.dialog-node-path', $hydra_node_dialog), /^\s*https?:\/\/[A-Za-z0-9\.\-_]+:\d+\/?\s*$/, "You must specify protocol, address, and port for a management uri", $hydra_node_tips);
						validation = validation && checkRegexp( $('.dialog-node-username', $hydra_node_dialog), /./, "You must specify a username", $hydra_node_tips);
						validation = validation && checkRegexp( $('.dialog-node-password', $hydra_node_dialog), /./, "You must specify a password", $hydra_node_tips);
						validation = validation && checkRegexp( $('.dialog-node-heads', $hydra_node_dialog), /^[1-8]$/, "You must specify a number of worker processes from 1 to 8", $hydra_node_tips);
						if ( validation ) {
							var password = $(".dialog-node-password", $hydra_node_dialog).val();
							var params = {
								node_name: $(".dialog-node-name", $hydra_node_dialog).val(),
								node: $.trim($(".dialog-node-path", $hydra_node_dialog).val()),
								username: $(".dialog-node-username", $hydra_node_dialog).val(),
								password: password,
								heads: $(".dialog-node-heads", $hydra_node_dialog).val()
							};
							that.saveHydraNode(params);
							$(this).dialog( "close" );
						}
					}
				}
			},
			close: function() {
					$(".dialog-field", $hydra_node_dialog).val( "" ).removeClass( "ui-state-error" );
				}
		});
		
		//Bind Button clickin' callbacks
		$(".hydra-node-add-button", this.container).button();
		$(".hydra-node-add-button-wrapper", this.container).show();
		$(".hydra-node-add-button", this.container).click(this.openAddDialog.bind(this));
	},
	//##################################################################################################
	// UTILITY FUNCTIONS
	//##################################################################################################
	saveHydraNode: function(params) {
		var uri = Splunk.util.make_url('custom', 'SA-Hydra' , 'hydra_conf_service', this.app, 'save_collection_node');
		if (params.node_name.length == 0) {
			delete params.node_name;
		}
		if (params.password.length == 0) {
			delete params.password;
		}
		var gate_key = this.gate_key;
		var $container = this.container;
		$(".hydra-node-edit-spinner", $container).show();
		$.ajax({
				type: "POST",
				url:uri,
				data:params,
				beforeSend: function(xhr) {
					xhr.setRequestHeader('X-Splunk-Form-Key', Splunk.util.getConfigValue("FORM_KEY"));
				},
				success: function(rsp, status) {
					console.log("[HydraNodeAdder] SUCCESS on hydra node save, updating interface...");
				},
				error: function(jqXHR,textStatus,errorThrown) {
					console.log("[HydraNodeAdder] AJAX Failure in save of hydra collection node");
				},
				complete: function() {
					console.log("[HydraNodeEditor] completed save attempt for hydra collection node");
					$(".hydra-node-edit-spinner", $container).hide();
					if (gate_key !== false) {
						$(document).trigger("openContextGate", [gate_key, params.node]);
					}
				}
		});
	},
	openAddDialog: function() {
		var context = this.getContext();
		$(".dialog-node-name", this.$hydra_node_dialog).val("");
		$(".dialog-node-path", this.$hydra_node_dialog).val("");
		$(".dialog-node-username", this.$hydra_node_dialog).val("");
		$(".dialog-node-password", this.$hydra_node_dialog).val("");
		$(".dialog-node-heads", this.$hydra_node_dialog).val("");
		this.$hydra_node_tips.html("");
		this.$hydra_node_dialog.dialog("open");
	},
	//##################################################################################################
	// MODULE FUNCTIONS
	//##################################################################################################
	resetUI: function() {
		this.$hydra_node_dialog.dialog("close");
	}
});
