function openTab(a, tabID) {
    $(".app-tab").addClass('w3-hide');
    $("#AppNavBar a").removeClass("w3-indigo");
    $(a).addClass("w3-indigo");
    $(tabID).removeClass('w3-hide');
    if (tabID == "#StatsTab") {
	update_stats();
    }
}

function update_inputsTable(data) {
    $('#fbInputsTab').html(data);
}

function update_fbModulesTable(data) {
    $('#fbModulesTab').html(data);
}

function update_mbModulesTable(data) {
    $('#mbModulesTab').html(data);
}

function update_statsTable(data) {
    $('#fbStatsContainer').html(data);
}

function update_stats() {
    $('#app-SyncButt').addClass('w3-spin');
    $.post('/get_stats', null, update_statsTable);
    setTimeout(function(){
	$('#app-SyncButt').removeClass('w3-spin');
    }, 1000);
}

function add_input() {
    var path = $("#fbPathInput").val();
    var field = $("#fbFieldInput").val();
    if (path && field) {
	$.post('/filebeat_add_input', {path: path, field: field}, update_inputsTable);
	$('#addInputModal').hide();
    }
}

function onIpInputEdited(input) {
    if ($(input).val()) {
	$("#probeSaveBtn").removeClass("w3-disabled");
    } else {
	$("#probeSaveBtn").addClass("w3-disabled");
    }
}

function onLicensekeyInputEdited(input) {
    if ($(input).val()) {
	$("#installAntivirusBtn").removeClass("w3-disabled");
    } else {
	$("#installAntivirusBtn").addClass("w3-disabled");
    }
}

function onFbInputEdited() {
    if ($("#fbFieldInput").val() && $("#fbPathInput").val()) {
	$("#fbSaveBtn").removeClass("w3-disabled");
    } else {
	$("#fbSaveBtn").addClass("w3-disabled");
    }
}

function save_settings() {
    var ip_addr = $("#ipInput").val();
    if (ip_addr) {
	$.post("/update_settings", {ip: ip_addr});
	$("#probeSaveBtn").addClass("w3-disabled");
    }
}

function install_antivirus() {
    var lkey = $("#licensekeyInput").val();
    if (lkey) {
	$.post("/install_antivirus", {licensekey: lkey});
	$("#installAntivirusBtn").addClass("w3-disabled");
    }
}

$(document).ready(function(){
    var homeTabLink = $("#HomeTabLink");
    homeTabLink.click();
});
