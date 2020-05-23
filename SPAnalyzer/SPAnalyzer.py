from itertools import combinations
import argparse
import json

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('--input',
                    help='input Site Policy file, take a look at example_manifests/')

CSP_KEYWORDS = {
    'unsafe-inline',
    'unsafe-eval',
    'nonce',
    'report-sample',
    'unsafe-hashes',
    'none',
    'strict-dynamic'
    'self',
    '*'
}


def check_csp(csps):
    """
    Checks whether one or all of the encountered CSP are nonce-based and checks for the presence of strict-dynamic
    """
    has_sd = False
    has_whitelist = False
    has_hash = False
    has_nonce = False
    has_unsafe_inline = False

    for csp in csps:
        this_has_hash = False
        this_has_nonce = False
        this_has_unsafe_inline = False
        this_has_sd = False
        this_has_wl = False

        for entry in csp:
            if entry.startswith('sha256-') or entry.startswith('sha384-') or entry.startswith('sha512-'):
                this_has_hash = True

        if 'nonce' in csp:
            this_has_nonce = True

        if not (this_has_hash or this_has_nonce) and 'unsafe-inline' in csp:
            this_has_unsafe_inline = True

        if 'strict-dynamic' in csp:
            this_has_sd = True

        if not this_has_sd:
            # check for whitelist as this is not disabled by s/d
            found_wl = False
            for entry in csp:
                if entry not in (CSP_KEYWORDS - {'*', 'self', 'none'}):
                    found_wl = True
        if len(csp) == 0:
            this_has_wl = True
        if (this_has_wl and this_has_sd) or (this_has_unsafe_inline and (this_has_nonce or this_has_hash)):
            raise Exception('Assertion failed ')

        has_hash |= this_has_hash
        has_nonce |= this_has_nonce
        has_unsafe_inline |= this_has_unsafe_inline
        has_whitelist |= this_has_wl
        has_sd |= this_has_sd

    return has_whitelist, has_nonce, has_unsafe_inline, has_sd, has_hash


def parse_CSP_string(csp_string):
    """
    Parses a given CSP string and returns a dict representation of the CSP.
    Only the "default-src" and "script-src" are used.
    :param csp_string:
    :return:
    """
    csp_dict = dict()
    csp_tokens = csp_string.split(';')
    for csp_token in csp_tokens:
        raw_policy = csp_token.strip().replace("'", "").replace("\"", "").split(' ')
        policy_directive = raw_policy[0]

        if policy_directive == '' or policy_directive == 'report-uri' or (
                policy_directive != "default-src" and policy_directive != "script-src"):
            # print("continue", policy_directive)
            continue

        if policy_directive not in csp_dict:
            csp_dict[policy_directive] = set()

        for raw_policy_token in raw_policy[1:]:
            if raw_policy_token.startswith("nonce"):
                csp_dict[policy_directive].add("nonce")
            else:
                csp_dict[policy_directive].add(raw_policy_token)

    return csp_dict


def is_csp_unsafe(csp_dict):
    if len(csp_dict.keys()) == 0:
        # emtpy string
        return 'Insecure'
    else:
        if 'script-src' in csp_dict:
            csp = set(csp_dict['script-src'])
        elif 'default-src' in csp_dict:
            csp = set(csp_dict['default-src'])
        else:
            return True
        has_whitelist, has_nonce, has_unsafe_inline, has_sd, has_hash = check_csp([csp])
        # print(csp, has_whitelist, has_nonce, has_unsafe_inline, has_sd, has_hash)
        if has_unsafe_inline:
            # check_csp enforces that it is only unsafe-inline if there are no nonces/hashes
            return 'Insecure'
        if not has_sd and len({'*', 'http:', 'https:', 'data:'} & csp):
            # we have not found s/d meaning that whitelists are enabled
            return 'Insecure'
    return 'Secure'


def check_all_hsts_greater_than_zero(pol_to_hsts):
    for hsts in pol_to_hsts.values():
        if hsts == '':
            # emtpy string leads to None here
            return False
        if hsts['max-age'] <= 0:
            return False
    return True


def is_cookie_default_secure(policy):
    if policy['<default>']['httponly'] and policy['<default>']['secure'] and (
            policy['<default>']['samesite'].lower() == 'lax' or policy['<default>']['samesite'].lower() == 'strict'):
        return 'Secure'
    return 'Insecure'


def main(args):
    parsed_sp = json.load(open(args.input))

    policyToCSPSecurity = dict()
    policy_to_parsed_HSTS = dict()
    policyToCookieSecureDefaults = dict()
    policyToDomainCookieSecureDefaults = dict()

    for pol_name in parsed_sp['csp-policies']:
        policyToCSPSecurity[pol_name] = is_csp_unsafe(parse_CSP_string(parsed_sp['csp-policies'][pol_name]))
    for pol_name in parsed_sp['hsts-policies']:
        policy_to_parsed_HSTS[pol_name] = parsed_sp['hsts-policies'][pol_name]
    for pol_name in parsed_sp['hostcookie-policies']:
        policyToCookieSecureDefaults[pol_name] = is_cookie_default_secure(parsed_sp['hostcookie-policies'][pol_name])

    for domain in parsed_sp['domaincookie-policies']:
        policyToDomainCookieSecureDefaults[domain] = is_cookie_default_secure(
            parsed_sp['domaincookie-policies'][domain])

    # check whether one of this
    ALL_CSP_SECURE = 'Insecure' not in policyToCSPSecurity.values()
    ALL_HSTS_SECURE = check_all_hsts_greater_than_zero(policy_to_parsed_HSTS)
    ALL_HOST_COOKIE_DEFAULTS_SECURE = 'Insecure' not in policyToCookieSecureDefaults.values()
    DOMAIN_COOKIE_DEFAULTS_SECURE = 'Insecure' not in policyToDomainCookieSecureDefaults.values()

    ALL_COOKIE_OPTOUTS_CONSISTENT = True
    for p1, p2 in combinations(parsed_sp['hostcookie-policies'], 2):
        policy1 = parsed_sp['hostcookie-policies'][p1]
        policy2 = parsed_sp['hostcookie-policies'][p2]
        for name in {*policy1.keys(), *policy2.keys()} - {'<default>'}:
            if name in policy1 and name in policy2:
                if not (policy1[name]['httponly'] == policy2[name]['httponly'] and
                        policy1[name]['secure'] == policy2[name]['secure'] and
                        policy1[name]['samesite'] == policy2[name]['samesite']):
                    ALL_COOKIE_OPTOUTS_CONSISTENT = False
                    print(
                        f'When comparing hostcookie policy {p1} with {p2} we have found an inconsistent opt-out for cookie with name {name}. Using this policies on the same host will result in inconsistent levels of security.')

    secure_csps = set(filter(lambda x: policyToCSPSecurity[x] == 'Secure', policyToCSPSecurity.keys()))
    insecure_csps = set(filter(lambda x: policyToCSPSecurity[x] == 'Insecure', policyToCSPSecurity.keys()))
    if not ALL_CSP_SECURE and len(secure_csps):
        print(
            f'Do not use a safe CSP from the set {secure_csps}, together with an unsafe CSP from the set {insecure_csps} on the same origin! This allows an attacker to compromise the complete origin once an XSS was found on a page protected by the unsafe CSP!')

    print(f"====================")
    print(f"All CSPs are safe: {ALL_CSP_SECURE}")
    print(f"HSTS cannot be deactivated on your site: {ALL_HSTS_SECURE}")
    print(f"All host cookies policies default securely: {ALL_HOST_COOKIE_DEFAULTS_SECURE}")
    print(f"All domain cookies policies default securely: {DOMAIN_COOKIE_DEFAULTS_SECURE}")
    print(f"All host cookie optouts are consistent: {ALL_COOKIE_OPTOUTS_CONSISTENT}")
    print(f"====================")


if __name__ == '__main__':
    args = parser.parse_args()
    main(args)
