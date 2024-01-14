function showResults(text) {
    document.getElementById("results").innerText = text;
}

async function invokeAndShowResults(url) {
    try {
        const response = await fetch(url);
        if (!response.ok) {
            msg = response.status + ' ' + response.statusText
            throw new Error(msg);
        }
        const json = await response.json();
        if (json === undefined) {
            msg = 'JSON retrieval error';
            throw new Error(msg);
        }
        if (!json.hasOwnProperty('message')) {
            msg = 'JSON has no message';
            throw new Error(msg);
        }
        showResults(json.message);
        if (!json.hasOwnProperty('data'))
            return undefined;
        return json.data;
    } catch (error) {
        showResults('ERROR: ' + error);
        return;
    }
}

function onClickTest() {
    invokeAndShowResults('test');
}

function onClickLogin() {
    window.location = 'login';
}

function onClickLogout() {
    window.location = 'logout';
}

async function onClickGetDriveFileList() {
    page_token = undefined;
    do {
        url = 'get_drive_file_list'
        if (page_token !== undefined) {
            url = url + '?page_token=' + page_token
        }
        data = await invokeAndShowResults(url);
        page_token = undefined;
        if (data !== undefined) {
            if (data.hasOwnProperty('page_token')) {
                page_token = data.page_token;
            }
        }
    } while (page_token !== undefined)
}

function onClickShowDriveFileList() {
    invokeAndShowResults('show_drive_file_list');
}

function onClickCalcFilesToChangeOwnership() {
    invokeAndShowResults('calc_files_to_change_ownership');
}

function onClickShowFilesNeedChangeOwnership() {
    invokeAndShowResults('show_files_need_change_ownership');
}

function onClickShowFilesToChangeOwnership() {
    invokeAndShowResults('show_files_to_change_ownership');
}

async function onClickChangeOwnership() {
    init = 'true';
    do {
        url = 'chown_files?init=' + init;
        init = 'false';
        data = await invokeAndShowResults(url);
        more = false;
        if (data !== undefined) {
            if (data.hasOwnProperty('more')) {
                more = data.more;
            }
        }
    } while (more === true);
}

function onClickShowPendingOwnership() {
    invokeAndShowResults('show_pending_ownership')
}

function onClickAcceptPendingOwnership() {
    invokeAndShowResults('accept_pending_ownership')
}