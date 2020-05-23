import hashlib
import re
from collections import defaultdict

import tldextract
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import psycopg2
from urllib.parse import urlparse

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
CACHE = {}


class URL(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, nullable=False)
    urlhash = db.Column(db.String(32), unique=True)
    content_type = db.Column(db.String(128), index=True)
    site = db.Column(db.String(1024), index=True)
    origin = db.Column(db.String(1024), index=True)


class Cookie(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('URL.id'), nullable=False)
    name = db.Column(db.String(1024), index=True)
    path = db.Column(db.String(1024))
    domain = db.Column(db.String(1024), index=True)
    hostonly = db.Column(db.Boolean, default=False, index=True)
    secure = db.Column(db.Boolean)
    httponly = db.Column(db.Boolean)
    samesite = db.Column(db.String(6))


class HSTS(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('URL.id'), nullable=False)
    value = db.Column(db.String(1024))
    value_hash = db.Column(db.String(32), index=True)
    max_age = db.Column(db.Integer)
    includesubdomains = db.Column(db.Boolean)


class CSP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('URL.id'), nullable=False)
    value = db.Column(db.String(4096))
    normalized_value = db.Column(db.String(4096))
    normalized_value_hash = db.Column(db.String(32), index=True)
    mitigates_xss = db.Column(db.Boolean)
    unsafe_inline = db.Column(db.Boolean)
    entire_scheme = db.Column(db.Boolean)


def parse_and_insert_cookie(cookie_string, url_id):
    if "=" not in cookie_string:
        return

    parts = cookie_string.split(";", 1)
    cookie_name = parts[0].split("=", 1)[0]
    cookie_domain = ''
    cookie_path = '/'
    cookie_secure = False
    cookie_httponly = False
    cookie_samesite = 'None'
    if len(parts) > 1:
        options = parts[1]
        for option in options.split(";"):
            if len(option.strip()) == 0:
                continue
            if option.strip().lower() == 'secure':
                cookie_secure = True
            elif option.strip().lower() == 'httponly':
                cookie_httponly = True
            elif "=" in option.strip().lower():
                if option.strip().lower().startswith('samesite'):
                    cookie_samesite = option.split("=")[1].strip().lower()
                elif option.strip().lower().startswith('domain'):
                    cookie_domain = option.split("=")[1].strip().lower()
                elif option.strip().lower().startswith('path'):
                    cookie_path = option.split("=")[1].strip().lower()

    cookie = Cookie(secure=cookie_secure,
                    httponly=cookie_httponly,
                    samesite=cookie_samesite,
                    domain=cookie_domain,
                    hostonly=cookie_domain == '',
                    name=cookie_name,
                    path=cookie_path,
                    url_id=url_id)
    db.session.add(cookie)
    db.session.commit()


def parse_csp(csp_string):
    """
    Takes a CSP string and parses it according to the specification
    :param csp_string: CSP to parse
    :return: dictionary with the directives and their values
    """
    # Let policy be a new policy with an empty directive set
    complete_policy = {}
    # For each token returned by splitting list on commas
    for policy_string in csp_string.lower().split(','):
        # Let policy be a new policy with an empty directive set
        policy = dict()
        # For each token returned by strictly splitting serialized on the U+003B SEMICOLON character (;):
        tokens = policy_string.split(';')
        for token in tokens:
            # Strip all leading and trailing ASCII whitespace from token.
            data = token.strip().split()
            # If token is an empty string, continue.
            if len(data) == 0:
                continue
            # Let directive name be the result of collecting a sequence of code points from token which are not ASCII
            # whitespace.
            while data[0] == ' ':
                data = data[1:]
                if len(data) == 0:
                    break
            # If token is an empty string, continue.
            if len(data) == 0:
                continue
            # Set directive name to be the result of running ASCII lowercase on directive name.
            directive_name = data[0]
            # If policy's directive set contains a directive whose name is directive name, continue.
            if directive_name in policy:
                continue
            # Let directive value be the result of splitting token on ASCII whitespace.
            directive_set = set()
            for d in data[1:]:
                if d.strip() != '':
                    directive_set.add(d)
            # Append directive to policy's directive set.
            policy[directive_name] = directive_set
        for name in policy:
            if name in complete_policy:
                if complete_policy[name] != policy[name]:
                    inter_sec = complete_policy[name].intersection(policy[name])
                    complete_policy[name] = inter_sec
                    continue
            complete_policy[name] = policy[name]
    # Return policy.
    return complete_policy


def normalize_single_csp(value):
    """
    takes in a CSP and normalizes it by removing random elements like nonces and the report-uri
    :param value: CSP to be normalized
    :return: normalized CSP
    """
    value = re.sub("'nonce-[^ ]+'", "'nonce'", value)
    value = re.sub("report-uri[^,;]+", "report-uri INSERTYOURURLHERE", value)
    value = re.sub("report-to[^,;]+", "report-to INSERTYOURURLHERE", value)
    parsed = parse_csp(value)
    final_value = ""
    for directive, expressions in sorted(parsed.items()):
        final_value += ("%s %s; " % (directive, " ".join(sorted(expressions)))).replace(" ;", ";")
    return final_value.strip().strip(";")


def parse_and_insert_csp(value, url_id):
    normalized_value = normalize_single_csp(value)
    nvh = hashlib.md5(normalized_value.encode()).hexdigest()
    parsed_csp = parse_csp(normalized_value)
    mitigates_xss, unsafe_inline, entire_scheme = False, False, False
    if "default-src" in parsed_csp or "script-src" in parsed_csp:
        mitigates_xss = True
        script_control = parsed_csp.get("script-src") or parsed_csp.get("default-src")
        if "'unsafe-inline'" in script_control:
            # determine if there is a nonce or hashes
            if "'nonce'" not in script_control and len([x for x in script_control if "'sha" in x]) == 0:
                unsafe_inline = True
        unsafe_sources = {"https://*", "http://*", "http:", "https:", "data:", "*"}
        # check for unsafe sources, but only if 'strict-dynamic' is not in policy
        if len(set(script_control) & unsafe_sources) and "'strict-dynamic'" not in script_control:
            entire_scheme = True

    csp = CSP(url_id=url_id,
              value=value,
              normalized_value=normalized_value,
              normalized_value_hash=nvh,
              mitigates_xss=mitigates_xss,
              unsafe_inline=unsafe_inline,
              entire_scheme=entire_scheme)
    db.session.add(csp)
    db.session.commit()


def parse_and_insert_hsts(value, url_id):
    data = {"max-age": None,
            "includesubdomains": False}
    for part in value.strip().strip(";").split(";"):
        if part.strip().lower().startswith("includesubdomains"):
            data["includesubdomains"] = True
        elif part.strip().lower().startswith("max-age"):
            try:
                data["max-age"] = int(part.strip().lower().split("=")[1].strip())
            except:
                pass
    hsts = HSTS(url_id=url_id,
                value=value,
                max_age=data["max-age"],
                includesubdomains=data["includesubdomains"])
    db.session.add(hsts)
    db.session.commit()


def cached_site_resolve(hostname):
    global CACHE
    if hostname not in CACHE:
        site = tldextract.extract(hostname).registered_domain
        CACHE[hostname] = site
    else:
        site = CACHE[hostname]
    return site


@app.route('/report_headers', methods=["POST"])
def report_headers():
    body = request.get_json()
    urlhash = hashlib.md5(body["url"].encode()).hexdigest()
    url_object = URL.query.filter_by(urlhash=urlhash).first()
    if url_object is None:
        parsed_url = urlparse(body["url"])
        origin = parsed_url.scheme + "://" + parsed_url.netloc
        site = cached_site_resolve(parsed_url.hostname)
        url_object = URL(urlhash=urlhash,
                         url=body["url"],
                         content_type=body.get("content-type", ""),
                         site=site,
                         origin=origin)
        db.session.add(url_object)
        db.session.commit()
    for header, value in body["headers"]:
        if header.lower() == 'set-cookie':
            parse_and_insert_cookie(value, url_object.id)
        if header.lower() == 'content-security-policy':
            parse_and_insert_csp(value, url_object.id)
        if header.lower() == 'strict-transport-security':
            parse_and_insert_hsts(value, url_object.id)

    return 'OK'


def get_minimal_security(cookie1, cookie2):
    new_cookie = {}
    if not cookie1["httponly"] or not cookie2["httponly"]:
        new_cookie["httponly"] = False
    else:
        new_cookie["httponly"] = True
    if not cookie1["secure"] or not cookie2["secure"]:
        new_cookie["secure"] = False
    else:
        new_cookie["secure"] = True
    if not cookie1["samesite"] or not cookie2["samesite"]:
        new_cookie["samesite"] = None
    else:
        union = set(cookie1["samesite"]) | set(cookie2["samesite"])
        if len(union) == 1:
            new_cookie["samesite"] = cookie1["samesite"]
        else:
            new_cookie["samesite"] = "lax"
    return new_cookie


def as_strict_as(cookie, httponly, secure, samesite):
    if httponly and not cookie["httponly"]:
        return False
    if secure and not cookie["secure"]:
        return False
    if samesite and not cookie["samesite"]:
        return False
    if samesite == 'lax' and cookie["samesite"] not in ('lax', 'strict'):
        return False
    if samesite == 'strict' and cookie["samesite"] != 'strict':
        return False
    return True


def generate_cookie_policy_for_origin(origin, default_policy):
    """
    Given an origin and a default policy, generates a cookie policy for the specific origin which includes all
    exemptions from the default. Given conflicting security properties for a cookie with the same name, it uses the less
    secure one to not break functionality.

    :param origin: origin for which to generate the policy
    :param default_policy: default level of cookie security
    :return: aggregated policy
    """
    entries = {}
    cookies = db.session.query(Cookie.name, Cookie.path, Cookie.httponly, Cookie.secure, Cookie.samesite).\
        join(URL).filter(URL.origin == origin, Cookie.hostonly == True).distinct().all()
    for cookie_name, cookie_path, httponly, secure, samesite in cookies:
        data = {"httponly": httponly, "secure": secure, "samesite": samesite}
        if cookie_name in entries:
            new_cookie = get_minimal_security(entries[cookie_name], data)
        else:
            new_cookie = data
        entries[cookie_name] = new_cookie

    cookie_policy = {"<default>": default_policy}
    if len(entries):
        for cookie_name, info in entries.items():
            if not as_strict_as(info, default_policy["httponly"],
                                default_policy["secure"],
                                default_policy["samesite"]):
                cookie_policy[cookie_name] = info

    return cookie_policy


def generate_csp_policies_for_origin(origin):
    """
    Given an origin, generates the different CSP policies as deployed on the origin.
    :param origin: origin for which to generate policies
    :return: the different CSP policies and a mapping between URLs and their chosen CSP policy
    """
    data = db.session.query(URL.url, CSP.normalized_value, CSP.normalized_value_hash). \
        join(CSP, isouter=True).filter(URL.origin == origin).distinct().all()
    csps = {}
    url_to_csp = {}
    for url, normalized_csp, nvh in data:
        if normalized_csp is not None:
            policy_id = nvh[:10]
        else:
            policy_id = 'csp_emtpy'
            normalized_csp = ''
        csps[policy_id] = normalized_csp
        url_to_csp[url] = policy_id

    return csps, url_to_csp


def generate_hsts_policies_for_origin(origin):
    """
    Given an origin, generates the different HSTS policies as deployed on the origin.
    :param origin: origin for which to generate policies
    :return: the different HSTS policies and a mapping between URLs and their chosen HSTS policy
    """
    data = db.session.query(URL.url, HSTS.value, HSTS.max_age, HSTS.includesubdomains).\
        join(HSTS, isouter=True).filter(URL.origin == origin).distinct().all()
    hsts = {}
    url_to_hsts = {}
    for url, hsts_value, max_age, includesubdomains in data:
        if hsts_value is not None:
            policy_id = "%s/%s" % (max_age, includesubdomains)
            policy = {"max-age": max_age, "includesubdomains": includesubdomains}
        else:
            policy_id = 'hsts_empty'
            policy = {}
        hsts[policy_id] = policy
        url_to_hsts[url] = policy_id

    return hsts, url_to_hsts


def generate_domaincookie_policy_for_origin(site, default_policy):
    """
    Given an site and a default policy, generates a cookie policy for the specific site which includes all
    exemptions from the default. Given conflicting security properties for a cookie with the same name, it uses the less
    secure one to not break functionality.

    :param site: site for which to generate the policy
    :param default_policy: default level of cookie security
    :return: aggregated policy
    """
    cookies = db.session.query(Cookie.name, Cookie.domain, Cookie.httponly, Cookie.secure, Cookie.samesite). \
        join(URL).filter(URL.site == site, Cookie.hostonly == False).distinct().all()

    entries = defaultdict(dict)

    for cookie_name, cookie_domain, httponly, secure, samesite in cookies:
        cookie_domain = cookie_domain.lstrip(".")
        data = {"httponly": httponly, "secure": secure, "samesite": samesite}
        if cookie_name in entries[cookie_domain]:
            new_cookie = get_minimal_security(entries[cookie_domain][cookie_name], data)
        else:
            new_cookie = data
        entries[cookie_domain][cookie_name] = new_cookie

    cookie_policy = defaultdict(dict)
    cookie_policy[site] = {"<default>": default_policy}
    if len(entries):
        for domain, cookie_entry in entries.items():
            for cookie_name, info in cookie_entry.items():
                if not as_strict_as(info, default_policy["httponly"],
                                    default_policy["secure"],
                                    default_policy["samesite"]):
                    cookie_policy[domain][cookie_name] = info
            cookie_policy[domain]["<default>"] = default_policy
    return cookie_policy


def get_distinct_origins(site):
    return db.session.query(URL.origin).filter(URL.site == site).distinct().all()


def get_all_urls_for_origin(origin):
    return db.session.query(URL.url).filter(URL.origin == origin).distinct().all()


@app.route('/get_manifest', methods=["POST"])
def get_manifest():
    body = request.get_json()
    site = body["site"]
    if "default-cookie-policy" in body:
        default_policy = body["default-cookie-policy"]
    else:
        # safe default cookie policy
        default_policy = {"secure": True, "httponly": True, "samesite": 'lax'}
    manifest = {"max-age": 900,
              "hsts-policies": {},
              "csp-policies": {},
              "hostcookie-policies": {},
              "policies": {},
              "default-policies": {}
              }

    origins = get_distinct_origins(site)

    url_mapping = {}

    for origin, in origins:
        host = origin.split("/")[2]
        cookie_policy = generate_cookie_policy_for_origin(origin, default_policy)
        manifest["hostcookie-policies"][host + "_hostcookie"] = cookie_policy
        manifest["hostcookie-policies"][host + "_hostcookie"]["<default>"] = default_policy
        csp_policies, csp_urls = generate_csp_policies_for_origin(origin)
        hsts_polices, hsts_urls = generate_hsts_policies_for_origin(origin)

        combo_to_policy_mapping = {}

        csps_hsts_combos = defaultdict(set)
        all_urls = get_all_urls_for_origin(origin)
        for url, in all_urls:
            csp_urls.get(url, '')
        # combine HSTS policies with CSP
        for url, hsts_policy_id in hsts_urls.items():
            csp_policy_id = csp_urls.get(url, 'csp_empty')
            csps_hsts_combos[(csp_policy_id, hsts_policy_id)].add(url)

        for policy_id, policy in hsts_polices.items():
            manifest["hsts-policies"][policy_id] = policy

        for policy_id, policy in csp_policies.items():
            manifest["csp-policies"][policy_id] = policy

            for i, (csp, hsts) in enumerate(csps_hsts_combos.keys()):
                hostcookie_id = host + "_hostcookie"
                policy_id = host + "_%d" % i
                manifest["policies"][policy_id] = {"csp": csp,
                                                 "hsts": hsts,
                                                 "hostcookie": hostcookie_id
                                                 }
                combo_to_policy_mapping[(csp, hsts)] = policy_id
            # we have exactly one policy for the origin, we might as well default to it
            if len(csps_hsts_combos) == 1:
                manifest["default-policies"][host] = host + "_0"

        # now map URLs to selected policies
        for combo, urls in csps_hsts_combos.items():
            for url in urls:
                url_mapping[url] = combo_to_policy_mapping[combo]

    manifest["domaincookie-policies"] = generate_domaincookie_policy_for_origin(site, default_policy)
    # we choose a safe, yet potentially breaking default policy
    manifest["csp-policies"]["default-csp"] = "script-src 'none'"
    manifest["hsts-policies"]["default-hsts"] = {"max-age": 31536000, "includesubdomains": True}
    manifest["hostcookie-policies"]["default-hostcookie"] = {"<default>": default_policy}
    manifest["policies"]["default"] = {"csp": "default-csp", "hsts": "default-hsts",
                                     "hostcookie": "default-hostcookie"}
    # check if there is a policy for the root origin already. If so, add the default for subdomains
    # by prepending the .
    if site in manifest["default-policies"]:
        manifest["default-policies"]["." + site] = "default"
    else:
        manifest["default-policies"][site] = "default"

    return jsonify({"manifest": manifest, "url_mapping": url_mapping})


if __name__ == '__main__':
    db.create_all()
    app.run()
