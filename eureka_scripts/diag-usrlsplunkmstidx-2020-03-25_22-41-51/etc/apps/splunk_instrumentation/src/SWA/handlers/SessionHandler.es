const NA = 'not available';

let newSession = null;

function strip(string, symb) {
    const end = string.indexOf(symb);
    if (end !== -1) {
        return string.substring(0, end);
    }
    return string;
}

function sessionGet(key) {
    return localStorage.getItem(key);
}

function sessionSet(key, value) {
    return localStorage.setItem(key, value);
}

// Getting CSRF Token from document.cookie, and remove the field name.
function getToken(token, regex) {
    if (regex.test(token)) {
        let match;
        match = token.match(regex);
        match = strip(match[match.length - 1], ';');
        return match.split('=')[1];
    }
    throw new Error("Can't access token");
}

function getOsInfo(userAgent) {
    if (!userAgent) {
        return {
            os: NA,
            osVersion: NA,
        };
    }
    let osName = '';
    let osVersion = '';

    /*
    s: os name
    r: regex for searching
    */

    const osInfo = [
        { s: 'Windows 10', r: /(Windows 10.0|Windows NT 10.0)/ },
        { s: 'Windows 8.1', r: /(Windows 8.1|Windows NT 6.3)/ },
        { s: 'Windows 8', r: /(Windows 8|Windows NT 6.2)/ },
        { s: 'Windows 7', r: /(Windows 7|Windows NT 6.1)/ },
        { s: 'Windows Vista', r: /Windows NT 6.0/ },
        { s: 'Windows Server 2003', r: /Windows NT 5.2/ },
        { s: 'Windows XP', r: /(Windows NT 5.1|Windows XP)/ },
        { s: 'Windows 2000', r: /(Windows NT 5.0|Windows 2000)/ },
        { s: 'Windows ME', r: /(Win 9x 4.90|Windows ME)/ },
        { s: 'Windows 98', r: /(Windows 98|Win98)/ },
        { s: 'Windows 95', r: /(Windows 95|Win95|Windows_95)/ },
        { s: 'Windows NT 4.0', r: /(Windows NT 4.0|WinNT4.0|WinNT|Windows NT)/ },
        { s: 'Windows CE', r: /Windows CE/ },
        { s: 'Windows 3.11', r: /Win16/ },
        { s: 'Android', r: /Android/ },
        { s: 'Open BSD', r: /OpenBSD/ },
        { s: 'Sun OS', r: /SunOS/ },
        { s: 'Ubuntu', r: /Ubuntu/ },
        { s: 'Linux', r: /(Linux|X11)/ },
        { s: 'iOS', r: /(iPhone|iPad|iPod)/ },
        { s: 'Mac OS X', r: /Mac OS X/ },
        { s: 'Mac OS', r: /(MacPPC|MacIntel|Mac_PowerPC|Macintosh)/ },
        { s: 'QNX', r: /QNX/ },
        { s: 'UNIX', r: /UNIX/ },
        { s: 'OS/2', r: /OS\/2/ },
    ];

    for (let i = 0; i < osInfo.length; i++) {
        const val = osInfo[i];
        if (val.r.test(userAgent)) {
            osName = val.s;
            break;
        }
    }

    if (/Windows/.test(osName)) {
        osVersion = /Windows (.*)/.exec(osName)[1];
        osName = 'Windows';
    }

    const versionInfo = {
        'Mac OS X': /Mac OS X (10[\._\d]+)/,
        Android: /Android ([\._\d]+)/,
        iOS: /OS (\d+)_(\d+)_?(\d+)?/,
    };

    if (versionInfo[osName]) {
        osVersion = '';
        const substring = versionInfo[osName].exec(userAgent);
        if (substring) {
            osVersion = substring[1].replace(/_/g, '.');
            osVersion = osVersion.substr(0, Math.min(osVersion.length, 5));
        }
    }

    return {
        osName,
        osVersion,
    };
}

function getBrowserInfo(userAgent) {
    if (!userAgent) {
        return {
            browserName: NA,
            browserVersion: NA,
        };
    }
    let browserName = '';
    let browserVersion = '';

    /*
    s: the browser name
    r: regex for searching name
    ofs: offset for Version
    ofsV: if userAgent has Version keyword, this is the offset we want
    */
    const browserInfo = [
            { s: 'Opera', r: 'Opera', ofs: 6, ofsV: 8 },
            { s: 'Opera', r: 'OPR', ofs: 4 },
            { s: 'Microsoft Edge', r: 'Edge', ofs: 5 },
            { s: 'Microsoft Internet Explorer', r: 'MSIE', ofs: 5 },
            { s: 'Chrome', r: 'Chrome', ofs: 7 },
            { s: 'Safari', r: 'Safari', ofs: 7, ofsV: 8 },
            { s: 'Firefox', r: 'Firefox', ofs: 8 },
            { s: 'Microsoft Internet Explorer', r: 'rv:', ofs: 3 },
            { s: 'Other', r: '' },
    ];
    const separator = [';', ' ', ')'];
    for (let i = 0; i < browserInfo.length; i++) {
        const browser = browserInfo[i];
        let offset;
        offset = userAgent.indexOf(browser.r);
        if (offset !== -1) {
            browserName = browser.s;
            browserVersion = userAgent.substring(offset + browser.ofs);
            offset = userAgent.indexOf('Version');
            if (offset !== -1) {
                browserVersion = userAgent.substring(offset + browser.ofsV);
            }
            break;
        }

    // special handling for other browser
        if (browser.s === 'Other') {
            const nameOffset = userAgent.lastIndexOf(' ') + 1;
            const verOffset = userAgent.lastIndexOf('/');
            browserName = userAgent.substring(nameOffset, verOffset);
            browserVersion = userAgent.substring(verOffset + 1);
            if (browserName.toLowerCase() === browserName.toUpperCase()) {
                browserVersion = window.navigator.appName;
            }
            break;
        }
    }

    separator.forEach((s) => {
        browserVersion = strip(browserVersion, s);
    });

    return {
        browserName,
        browserVersion,
    };
}

function generateExperienceID() {
    function seed() {
        return Math.floor((1 + Math.random()) * 0x10000)
          .toString(16)
          .substring(1);
    }
    return `${seed()}${seed()}-${seed()}-${seed()}-${seed()}-${seed()}${seed()}${seed()}`;
}

function sendEvent(factory, options) {
    let platform;
    let userAgent;

    if (window.navigator) {
        userAgent = window.navigator.userAgent;
        platform = window.navigator.platform;
    }

    const osInfo = getOsInfo(userAgent);
    const browserInfo = getBrowserInfo(userAgent);

    const event = {
        type: 'session_start',
        data: {
            device: platform || NA,
            os: osInfo.osName || NA,
            osVersion: osInfo.osVersion || NA,
            locale: window.$C.LOCALE || NA,
            browser: browserInfo.browserName || NA,
            browserVersion: browserInfo.browserVersion || NA,
            splunkVersion: window.$C.VERSION_LABEL || NA,
            guid: options.instanceGUID,
        },
    };
    factory(event);
}


function SessionHandler(factory, options) {
    if (newSession) {
        sendEvent(factory, options);
        newSession = false;
    }
}

SessionHandler.init = function (options) {
    const savedToken = sessionGet(options.savedTokenKey);
    const pattern = options.cookieRegex;
    const token = getToken(document.cookie, pattern);
    let experienceID = sessionGet(options.experienceIDKey);

    if (savedToken !== token || !experienceID) {
        newSession = true;
        experienceID = generateExperienceID();
        sessionSet(options.savedTokenKey, token);
        sessionSet(options.experienceIDKey, experienceID);
    }

    const update = {
        experienceID: sessionGet(options.experienceIDKey),
    };

    options.updateOptions(update);
};


export { SessionHandler, getOsInfo, getBrowserInfo, getToken };
