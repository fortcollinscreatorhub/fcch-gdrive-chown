// Copyright (c) 2024 Stephen Warren
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

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

function onClickLogin() {
    window.location = 'login';
}

function onClickLogout() {
    window.location = 'logout';
}

async function onClickGetDriveFileList() {
    showResults("Running...");
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
    showResults("Running...");
    invokeAndShowResults('show_drive_file_list');
}

function onClickCalcFilesToChangeOwnership() {
    showResults("Running...");
    invokeAndShowResults('calc_files_to_change_ownership');
}

function onClickShowFilesNeedChangeOwnership() {
    showResults("Running...");
    invokeAndShowResults('show_files_need_change_ownership');
}

function onClickShowFilesToChangeOwnership() {
    showResults("Running...");
    invokeAndShowResults('show_files_to_change_ownership');
}

async function onClickChangeOwnership() {
    showResults("Running...");
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
    showResults("Running...");
    invokeAndShowResults('show_pending_ownership')
}

async function onClickAcceptPendingOwnership() {
    showResults("Running...");
    init = 'true';
    do {
        url = 'accept_pending_ownership?init=' + init;
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
