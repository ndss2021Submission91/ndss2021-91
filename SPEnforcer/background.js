const SHOULD_COLLECT_HEADERS = true;
const COLLECTION_SERVER = 'http://127.0.0.1:5000/report_headers';
const INTERESTING_HEADER = new Set(['set-cookie', 'strict-transport-security', 'content-security-policy']);

let SITES_TO_POLICIES = {
    'sptest.com': {
        "max-age": 900,
        "default_policies": {
            "sptest.com": "policy_default"
        },
        "hsts-policies": {
            "default-hsts": {
                "max-age": 31536000,
                "includeSubDomains": true
            }
        },
        "csp-policies": {
            "csp_emtpy": "",
            "default-csp": "script-src 'self'"
        },
        "hostcookie-policies": {
            "cookie_pol": {
                "<default>": {
                    "secure": true,
                    "httponly": false,
                    "samesite": "None"
                },
                "test1": {
                    "samesite": "Lax",
                    "secure": false,
                    "httponly": false,

                },
                "test2": {
                    "samesite": "Strict",
                    "secure": true,
                    "httponly": false
                }
            }
        },
        "policies": {
            "policy_default": {
                "hostcookie": "cookie_pol",
                "csp": "default-csp",
                "hsts": "default-hsts"
            }
        },
        "default-policies": {
            "sptest.com": "policy_default",
        },
        "domaincookie-policies": {
            "sptest.com": {
                "<default>": {
                    "secure": true,
                    "httponly": true,
                    "samesite": "lax"
                }
            }
        }
    }
};


const SAME_SITE_ENUM = {
    'None': 0,
    'Lax': 1,
    'Strict': 2
};

function getSite(url) {
    let parsed = new URL(url);
    let parsed_psl = psl.parse(parsed.hostname);
    return parsed_psl.domain;
}

function getSitePolicyIfStored(url, policy_identifier = undefined) {
    let parsed = new URL(url);
    let site = getSite(url);
    if (SITES_TO_POLICIES[site]) {
        let selected_policy;
        if (policy_identifier) {
            selected_policy = SITES_TO_POLICIES[site]['policies'][policy_identifier]
        } else {
            let default_policies_domains = Object.keys(SITES_TO_POLICIES[site]['default_policies']);
            let sorted_default_policies_domains = default_policies_domains.sort(function (a, b) {
                return b.length - a.length;
            });
            let match;
            // FIXME: do only domain matches in real implementation this does substring matches but serves as starting point
            for (let domain_part of sorted_default_policies_domains) {
                if (parsed.hostname.indexOf(domain_part) !== -1) {
                    match = domain_part;
                }
            }
            selected_policy = SITES_TO_POLICIES[site]['default_policies'][match];
            selected_policy = SITES_TO_POLICIES[site]['policies'][selected_policy];
        }
        return [selected_policy, SITES_TO_POLICIES[site]];
    }
    return [undefined, undefined];
}

function parseHSTS(hsts_header) {
    let splitted = hsts_header.split(';');
    let max_age = undefined;
    let keywords = new Set();
    for (let entry of splitted) {
        entry = entry.trim().toLowerCase();
        if (entry.startsWith('max-age')) {
            max_age = parseInt(entry.substr(8))
        } else if (entry === 'includesubdomains' || entry === 'preload') {
            keywords.add(entry)
        }
    }
    if (max_age !== undefined && !isNaN(max_age)) {
        return {"max-age": max_age, keywords: keywords}
    }
    return undefined;
}

function parseCookieKeywords(cookie_header, hostname, name = undefined) {
    let splitted = cookie_header.split(';');
    let samesite = undefined;

    let keywords = new Set();
    let domain = undefined;
    let path = '/';
    let c_name;
    let c_val;

    if (name === undefined) {
        // this is a real cookie header, thus we need to parse the first entry as key/value
        [c_name, c_val] = splitted.shift().split('=', 1)
    }

    for (let entry of splitted) {
        entry = entry.trim();
        if (entry.toLowerCase() === 'secure' || entry.toLowerCase() === 'httponly') {
            keywords.add(entry.toLowerCase());
        } else if (entry.indexOf('=') !== -1) {
            let splitted_sub = entry.split('=', 2);
            if (splitted_sub[0].toLowerCase() === 'domain') {
                domain = splitted_sub[1];
            } else if (splitted_sub[0].toLowerCase() === 'path') {
                path = splitted_sub[1];
            } else if (splitted_sub[0].toLowerCase() === 'samesite') {
                if (splitted_sub[1] === 'None' || splitted_sub[1] === 'Lax' || splitted_sub[1] === 'Strict') {
                    samesite = splitted_sub[1];
                }
                // SameSite standard is really weird on this one, directives are case-insensitive but SameSite values are case-sensitive
                // https://tools.ietf.org/html/draft-west-first-party-cookies-07 section 4.1
            }
        }
    }
    return {"name": c_name, "keywords": keywords, "samesite": samesite, "path": path, "domain": domain}

}

function composeHSTS(parsed_hsts) {
    return `max-age=${parsed_hsts['max-age']};${[...parsed_hsts['keywords']].join(';')}`
}

function getPolicyForCookieName(policy, name) {
    if (policy[name] !== undefined) {
        return policy[name];
    }
    return policy['<default>'];
}

function matchDomainCookiePolicy(set_domain, complete_policy) {
    let domains = Object.keys(complete_policy['domaincookie-policies']);
    let sorted_domains = domains.sort(function (a, b) {
        return b.length - a.length;
    });
    let match;
    // FIXME: do only domain matches in real implementation this does substring matches but serves as starting point
    for (let domain_part of sorted_domains) {
        if (set_domain.indexOf(domain_part) !== -1) {
            match = domain_part;
        }
    }
    // matches are guaranteed due to mandated domain.com
    return complete_policy['domaincookie-policies'][match];
}

function applyPolicyToHeaders(headers, specific_policy, complete_policy, url) {
// FIXME: we should apply these mechanisms only when needed, e.g., CSP is useless on non documents. But it does not break anything.
    let changed_headers = [];
    let parsed = new URL(url);
    let hostname = parsed.hostname;

    let found_hsts = false;

    let selected_hsts = complete_policy['hsts-policies'][specific_policy['hsts']];
    let selected_csp = complete_policy['csp-policies'][specific_policy['csp']];
    let selected_hostcookies = complete_policy['hostcookie-policies'][specific_policy['hostcookie']];

    for (let header of headers) {
        let header_name = header.name.trim();
        let header_value = header.value.trim();
        switch (header_name.toLowerCase()) {
            case 'set-cookie':
                let header_string = header_value;
                let cookie_policy = parseCookieKeywords(header_string);
                let cookie_type;

                let selected_cookie_policy;
                if (cookie_policy['domain'] === undefined) {
                    // we have a host cookie
                    selected_cookie_policy = selected_hostcookies;
                    cookie_type = 'host'
                } else {
                    selected_cookie_policy = matchDomainCookiePolicy(cookie_policy['domain'], complete_policy);
                    cookie_type = 'domain'
                }
                let sp_cookie_policy = getPolicyForCookieName(selected_cookie_policy, cookie_policy['name']);

                // we can parse the keywords only now
                for (let keyword of ['secure', 'httponly']) {
                    if (!cookie_policy['keywords'].has(keyword) && sp_cookie_policy[keyword] === true) {
                        header_string += ';' + keyword;
                        console.log(`Upgraded ${cookie_type} Cookie ${cookie_policy['name']}: Enabled ${keyword}`);
                    }
                }
                if (cookie_policy['samesite'] !== undefined) {
                    let max_samesite_value = [cookie_policy['samesite'], sp_cookie_policy['samesite']].reduce(function (prev, cur) {
                        let num_prev = SAME_SITE_ENUM[prev] === undefined ? -1 : SAME_SITE_ENUM[prev];
                        let num_cur = SAME_SITE_ENUM[cur] === undefined ? -1 : SAME_SITE_ENUM[cur];
                        if (num_prev > num_cur) {
                            return prev;
                        }
                        return cur;
                    });
                    if (max_samesite_value !== cookie_policy['samesite']) {
                        header_string = header_string.replace(/samesite=\w+/gi, 'SameSite=' + max_samesite_value);
                        console.log(`Upgraded ${cookie_type} Cookie ${cookie_policy['name']}: Enabled SameSite=${max_samesite_value}`);
                    }
                } else {
                    // this case is easy as we can just append the new directive
                    header_string += '; SameSite=' + sp_cookie_policy['samesite'];
                    console.log(`Upgraded ${cookie_type} Cookie ${cookie_policy['name']}: Enabled SameSite=${sp_cookie_policy['samesite']}`);
                }
                changed_headers.push({'name': header_name, value: header_string});
                break;
            case 'strict-transport-security':
                found_hsts = true;
                let sent_hsts = parseHSTS(header_value);
                if (sent_hsts === undefined) {
                    console.error('Could not parse HSTS header supplied by the application', header_value);
                    continue;
                }
                let composed_hsts = {
                    "max-age": Math.max(sent_hsts["max-age"], selected_hsts["max-age"]),
                    "keywords": new Set([...sent_hsts["keywords"]])
                };
                if (selected_hsts["includeSubDomains"]) {
                    composed_hsts['keywords'].add('includesubdomains')
                }
                changed_headers.push({'name': header_name, value: composeHSTS(composed_hsts)});
                console.log('Merged ', sent_hsts, 'and', selected_hsts, 'to', composeHSTS(composed_hsts));
                break;
            case 'content-security-policy':
                // FIXME: to test generated CSPs we throw away all other CSPs, for the correct mechanism leave them here
                break;
            default:
                // we do not touch the header if its is not any of the ones we need to check minimal security guarantees on
                changed_headers.push({'name': header_name, value: header_value});
        }
    }
    // Add HSTS from policy if we did not merge already
    if (!found_hsts && selected_hsts !== '') {
        let composed_hsts = `max-age=${selected_hsts['max-age']}`;
        if (selected_hsts['includeSubDomains']) {
            composed_hsts += '; includeSubDomains';
        }
        changed_headers.push({'name': 'strict-transport-security', value: composed_hsts});
        console.log('Did not find valid HSTS, enforcing default:', composed_hsts)
    }
    // Always add the CSP that should be applied to this resource
    if (selected_csp !== '') {
        changed_headers.push({'name': 'content-security-policy', value: selected_csp});
        console.log('Enforcing default CSP:', selected_csp)
        // FIXME: replace nonces with client-side generated nonces => not yet supported by browsers
    }
    return changed_headers;
}


function collectRelevantHeaders(details) {
    let headers = details.responseHeaders;
    let url = details.url;
    if (url.indexOf(COLLECTION_SERVER) > -1) {
        return;
    }
    let collection = [];
    let contenttype;
    for (let header of headers) {
        let header_name = header.name.trim().toLowerCase();
        let header_value = header.value.trim();
        if (INTERESTING_HEADER.has(header_name)) {
            collection.push([header_name, header_value])
        }
        if (header_name === 'content-type') {
            contenttype = header_value;
        }
    }
    fetch(COLLECTION_SERVER, {
        method: "POST",
        body: JSON.stringify({
            "url": url,
            "headers": collection,
            "content-type": contenttype
        }),
        headers: {
            'Content-Type': 'application/json'
            // 'Content-Type': 'application/x-www-form-urlencoded',
        },
    })
}

chrome.webRequest.onHeadersReceived.addListener(details => {
    if (SHOULD_COLLECT_HEADERS) {
        if (details.type == 'main_frame' || details.type == 'sub_frame')
            collectRelevantHeaders(details)
    }

    let [specific_policy, complete_policy] = getSitePolicyIfStored(details.url);
    if (specific_policy) {
        let changed_headers = applyPolicyToHeaders(details.responseHeaders, specific_policy, complete_policy, details.url);
        console.log('Final changed headers:', changed_headers);
        return {responseHeaders: changed_headers};
    }
    return {responseHeaders: details.responseHeaders};
}, {urls: ["*://*/*"]}, ['blocking', 'responseHeaders', 'extraHeaders']);

chrome.runtime.onMessage.addListener(function (msg, sender, respond) {
    if (msg.action === 'isSPenabled') {
        let site = getSite(msg.url);
        if (SITES_TO_POLICIES[site] !== undefined) {
            respond({text: 'SP was FOUND for site ' + site, sp: JSON.stringify(SITES_TO_POLICIES[site]), site: site});
        } else {
            respond({text: 'SP was NOT FOUND for site ' + site, sp: '', site: site})
        }
    } else if (msg.action === 'setSP') {
        SITES_TO_POLICIES[msg.site] = JSON.parse(msg.policy);
        respond('SP was set for ' + msg.site);
    }
});