// IE9 and IE10 fix
if(!window.console) {
	var console = {
		log : function(){},
		warn : function(){},
		error : function(){}
	}
 }
Splunk.Module.HydraNodeEditor = $.klass(Splunk.Module, {
	initialize: function($super, container) {
		$super(container);
		//Set up internal variables
		this.app = this.getParam("app");
		this.gate_key = this.getParam("gate_key", false);
		this.node_stanza = this.getParam("node_stanza");
		this.node_path = this.getParam("node_path");
		this.node_user = this.getParam("node_user");
		this.node_heads = this.getParam("node_heads");
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
		var $hydra_node_delete_dialog = $(".hydra-delete-confirm-dialog", this.container).dialog({
			autoOpen: false,
			dialogClass: "conf-dialog",
			resizable: false,
			height: 200,
			width: 400,
			modal: true,
			buttons: {
				Cancel: {
					class: 'left-button',
					text: 'Cancel',
					click: function() {
						$( this ).dialog( "close" );
					}
				},
				"Delete Node": {
					class: 'right-redbutton',
					text: 'Delete Node',
					click: function() {
                        $(".dialog-field", $hydra_node_dialog).removeClass( "ui-state-error" );
						var node_path = $(".dialog-node-path", $hydra_node_dialog).val();
				        that.deleteHydraNode(node_path);
				        $(this).dialog( "close" );
                    }
                }
            }
        });	
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
				"Delete Node": {
					class: 'left-redbutton',
					text: 'Delete Node',
					click: function() {
                        $hydra_node_delete_dialog.dialog("open");
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
							//if password is the default we set it to empty string to indicate no change
							password = password == "$$$$$$$$" ? "" : password;
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
					console.log("[HydraNodeEditor] SUCCESS on hydra node save, updating interface...");
				},
				error: function(jqXHR,textStatus,errorThrown) {
					console.log("[HydraNodeEditor] AJAX Failure in save of hydra collection node");
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
	

    //Delete Hydra node
    deleteHydraNode: function(node) {
		var uri = Splunk.util.make_url('custom', 'SA-Hydra' , 'hydra_conf_service', this.app, 'delete_collection_node', encodeURIComponent(node));
        var gate_key = this.gate_key;
		var $container = this.container;
		$(".hydra-node-edit-spinner", $container).show();
		$.ajax({
				type: "DELETE",
				url:uri,
				beforeSend: function(xhr) {
					xhr.setRequestHeader('X-Splunk-Form-Key', Splunk.util.getConfigValue("FORM_KEY"));
				},
				success: function(rsp, status) {
					console.log("[HydraNodeEditor] SUCCESS on hydra node delete");
				},
				error: function(jqXHR,textStatus,errorThrown) {
					console.log("[HydraNodeEditor] AJAX Failure in delete of hydra collection node");
				},
				complete: function() {
					console.log("[HydraNodeEditor] completed delete attempt for hydra collection node");
					$(".hydra-node-edit-spinner", $container).hide();
					if (gate_key !== false) {
						$(document).trigger("openContextGate", [gate_key, node]);
					}
				}
		});
	},

	//##################################################################################################
	// MODULE FUNCTIONS
	//##################################################################################################
	onContextChange: function() {
		var context = this.getContext();
		$(".dialog-node-name", this.$hydra_node_dialog).val(context.get(this.node_stanza));
		$(".dialog-node-path", this.$hydra_node_dialog).val(context.get(this.node_path));
		$(".dialog-node-username", this.$hydra_node_dialog).val(context.get(this.node_user));
		//Set the password to 8 dollar signs to show that this node exists and password can be edited
		$(".dialog-node-password", this.$hydra_node_dialog).val("$$$$$$$$");
		$(".dialog-node-heads", this.$hydra_node_dialog).val(context.get(this.node_heads));
		//Set title to edit one
		this.$hydra_node_tips.html("");
		this.$hydra_node_dialog.dialog("open");
	},
	resetUI: function() {
		this.$hydra_node_dialog.dialog("close");
	}
});
