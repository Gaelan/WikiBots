"""A wikipedia bot that attemps to automatically fix broken URLs in CS1 citations."""

import urllib.parse
import requests
import mwparserfromhell
import regex
import pywikibot
import itertools


def is_scheme(scheme):
    """Port of is_scheme from Module:Citation/CS1. Unlike that function, this doesn't expect a
    trailing : on the scheme.
    """
    return regex.match(r"^[a-z][a-z\d\+\.\-]*$", scheme)


def is_domain_name(domain):
    """Port of is_domain_name from Module:Citation/CS1."""
    if not regex.match(r"^[a-z\d]", domain):
        return False

    if regex.match(r"^[a-z]+:", domain):
        return False

    # Below logic uses lua regexes, which don't translate directly into python regexes. For now,
    # we ignore them. This shouldn't be a problem, because all of our fixes are based around the
    # space and scheme checks.
    return True

    # if regex.match(r"\f[a-z\d][a-z\d][a-z\d\-]+[a-z\d]\.[a-z][a-z]+$", domain):
    #     return True
    # elif regex.match(r"\f[a-z\d][a-z\d][a-z\d\-]+[a-z\d]\.xn\-\-[a-z\d]+$", domain):
    #     return True
    # elif regex.match(r"\f[a-z\d][a-z\d]\.cash$", domain):
    #     return True
    # elif regex.match(r"\f[a-z\d][a-z\d]\.org$", domain):
    #     return True
    # elif regex.match(r"\f[a-z][qxz]\.com$", domain):
    #     return True
    # elif regex.match(r"\f[a-z][iq]\.net$", domain):
    #     return True
    # elif regex.match(r"\f[a-z\d][a-z\d]\.[a-z][a-z]$", domain):
    #     return True
    # elif regex.match(r"\f[a-z\d][a-z\d][a-z\d]\.[a-z][a-z]+$", domain):
    #     return True
    # elif regex.match(r"^\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?", domain):
    #     return True
    # else:
    #     return False


def valid_url(url):
    """Is the URL valid, according to Module:Citation/CS1?"""
    # This is a port of the check_url function in that module.

    url = url.strip()

    if not regex.match(r"^\S+$", url):
        return False

    parsed = urllib.parse.urlparse(url)

    return is_scheme(parsed.scheme) and is_domain_name(parsed.netloc)


def real_url(url):
    """Does this URL actually work? Checks valid_url as well."""
    if not valid_url(url):
        return False

    try:
        res = requests.get(url, timeout=10)
        return res.status_code == 200
    except (requests.exceptions.ConnectionError, requests.exceptions.InvalidURL):
        return False


def https_fix(url):
    """Try adding an https schema"""
    return "https://" + url


def http_fix(url):
    """Try adding an http schema"""
    return "http://" + url


def despace_fix(url):
    """Try removing spaces."""
    split = url.split(" ")
    if not len(split) == 2:
        return None
    if "/" not in split[0]:
        return None
    if "/" not in split[1]:
        return None
    return split[0] + split[1]


FIXES = [https_fix, http_fix, despace_fix]


def main():
    """Do the thing."""
    count = 0
    site = pywikibot.Site("en", "wikipedia")
    cat = pywikibot.Category(site, "Pages with URL errors")
    for art in itertools.islice(cat.articles(), 200):
        print("Trying to fix " + art.title())
        text = mwparserfromhell.parse(art.text)

        citations = [
            temp
            for temp in text.filter_templates()
            if temp.name.lower().startswith("cite")
        ]

        broken_citations = [
            cite
            for cite in citations
            if cite.has("url") and not valid_url(str(cite.get("url").value))
        ]

        for cite in broken_citations:
            url = str(cite.get("url").value)
            successful = False
            for fix in FIXES:
                fixed = fix(url)
                if fixed and real_url(fixed):
                    print("Changed " + url + " to " + fixed + " with " + fix.__name__)
                    count += 1
                    successful = True
                    break
            # if not successful:
            #     print("Couldn't fix " + url)
    print("Fixed " + str(count))


main()
