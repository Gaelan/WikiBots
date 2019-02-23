"""A wikipedia bot that attemps to automatically fix broken URLs in CS1 citations."""

import urllib.parse
from collections import Counter
import sys

import itertools
import requests
import mwparserfromhell
import regex
from termcolor import colored

import pywikibot


def is_scheme(scheme):
    """Port of is_scheme from Module:Citation/CS1. Unlike that function, this doesn't expect a
    trailing : on the scheme.
    """
    return regex.search(r"^[a-z][a-z\d\+\.\-]*$", scheme)


def is_domain_name(domain):
    """Port of is_domain_name from Module:Citation/CS1."""
    if not regex.search(r"^[a-z\d]", domain):
        return False

    if regex.search(r"^[a-z]+:", domain):
        return False

    # Below logic uses lua regexes, which don't translate directly into python regexes. For now,
    # we ignore them. This shouldn't be a problem, because all of our fixes are based around the
    # space and scheme checks.
    # return True

    if regex.search(r"(?<![a-z\d])[a-z\d][a-z\d\-]+[a-z\d]\.[a-z][a-z]+$", domain):
        return True
    elif regex.search(r"(?<![a-z\d])[a-z\d][a-z\d\-]+[a-z\d]\.xn\-\-[a-z\d]+$", domain):
        return True
    elif regex.search(r"(?<![a-z\d])[a-z\d]\.cash$", domain):
        return True
    elif regex.search(r"(?<![a-z\d])[a-z\d]\.org$", domain):
        return True
    elif regex.search(r"(?<![a-z])[qxz]\.com$", domain):
        return True
    elif regex.search(r"(?<![a-z])[iq]\.net$", domain):
        return True
    elif regex.search(r"(?<![a-z\d])[a-z\d]\.[a-z][a-z]$", domain):
        return True
    elif regex.search(r"(?<![a-z\d])[a-z\d][a-z\d]\.[a-z][a-z]+$", domain):
        return True
    elif regex.search(r"^\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?", domain):
        return True
    else:
        return False


def get_template(string):
    """Attempt to parse a string as a templete. Returns None on failure."""

    parsed = mwparserfromhell.parse(string)
    if len(parsed.nodes) == 1 and isinstance(
        parsed.nodes[0], mwparserfromhell.nodes.template.Template
    ):
        return parsed.nodes[0]
    return None


def valid_template(template):
    """Is this a template that returns a valid URL?"""
    if template.name.lower() == "google books" and (
        template.has("plainurl") or template.has("plain-url")
    ):
        return True
    if template.name.lower() == "billboardurlbyname":
        return True
    return False


def valid_url(url):
    """Is the URL valid, according to Module:Citation/CS1?"""
    # This is based on the check_url function in that module.

    url = url.strip()

    template = get_template(url)

    if template:
        return valid_template(template)

    if not regex.search(r"^\S+$", url):
        return False

    try:
        parsed = urllib.parse.urlparse(url)

        return is_scheme(parsed.scheme) and is_domain_name(parsed.netloc)
    except ValueError:
        return False


def real_url(url):
    """Does this URL actually work? Checks valid_url as well."""
    if not valid_url(url):
        return False

    if get_template(url):
        # Assume that correctly configured, a template returns a valid URL.
        return True

    try:
        res = requests.get(url, timeout=10, allow_redirects=False)
        return res.status_code == 200
    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.InvalidURL,
        requests.exceptions.InvalidSchema,
        requests.exceptions.ReadTimeout,
    ):
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
    url_ish_re = r"[/&=]"
    if not regex.search(url_ish_re, split[0]):
        return None
    if not regex.search(url_ish_re, split[1]):
        return None
    return split[0] + split[1]


def broken_schema_fix(url):
    """Try replacing :/ and // with ://."""
    url = regex.sub(r"(?<=[a-z]):/(?=[a-z])", "://", url)
    url = regex.sub(r"(?<=[a-z])//(?=[a-z])", "://", url)
    return url


def double_schema_fix(url):
    """Try removing double schemas."""
    parts = url.split("://")
    if len(parts) != 3:
        return None

    if not regex.search(r"^[a-z]*$", parts[0]):
        return None

    if not regex.search(r"^[a-z]*$", parts[1]):
        return None

    return f"{parts[0]}://{parts[2]}"


def idn_fix(url):
    """Try converting to IDN format."""
    try:
        parsed = urllib.parse.urlparse(url.strip())
        return urllib.parse.urlunparse(
            parsed._replace(netloc=str(parsed.netloc.encode("idna").decode("UTF-8")))
        )
    except (ValueError, UnicodeError):
        return None


def google_books_fix(url):
    """Try adding plainurl=yes to {{google books}}"""
    template = get_template(url)
    if (
        template
        and template.name.lower() == "google books"
        and not template.has("plainurl")
        and not template.has("plain-url")
    ):
        template.add("plainurl", "yes")
    return str(template)


def extraneous_symbols_fix(url):
    return (
        url.replace("[", "")
        .replace("]", "")
        .replace("<", "")
        .replace(">", "")
        .replace("'", "")
    )


FIXES = [
    https_fix,
    http_fix,
    # idn_fix,
    google_books_fix,
    broken_schema_fix,
    double_schema_fix,
    despace_fix,
    extraneous_symbols_fix,
]


def main():
    """Do the thing."""
    limit = None
    if len(sys.argv) > 1:
        limit = int(sys.argv[1])
    count = 0
    strategy_stats = Counter()
    site = pywikibot.Site("en", "wikipedia")
    cat = pywikibot.Category(site, "Pages with URL errors")
    for art in cat.articles(namespaces=[0, 118]):
        if art.botMayEdit():
            edited_article = False
            used_fixes = set()
            fixes_made = 0
            text = mwparserfromhell.parse(art.text)

            citations = [
                temp
                for temp in text.filter_templates()
                if temp.name.lower().startswith("cite")
            ]

            broken_citations = [
                cite
                for cite in citations
                if cite.has("url")
                and cite.get("url").value != ""
                and not valid_url(str(cite.get("url").value))
            ]

            for cite in broken_citations:
                url = str(cite.get("url").value)
                successful = False
                for fix in FIXES:
                    fixed = fix(url)
                    if fixed and real_url(fixed):
                        print(
                            colored(
                                f"[{art.title()}] [{fix.__name__}] {url} -> {fixed}",
                                "green",
                            )
                        )
                        if not edited_article:
                            count += 1
                            edited_article = True
                            strategy_stats[fix.__name__] += 1
                        successful = True
                        fixes_made += 1
                        used_fixes.add(fix.__name__)
                        cite.add("url", fixed)
                        break
                if not successful:
                    print(colored(f"[{art.title()}] {url}", "red"))

            if fixes_made > 0:
                summary = f"Attempted to automatically fix {fixes_made} citation URL(s). Strategies used: {', '.join(used_fixes)}. Questions? Mistake? Contact [[User talk:Gaelan]]."
                try:
                    art.put(str(text), summary=summary)
                except pywikibot.exceptions.LockedPage:
                    pass

            if limit and (count == limit):
                break

    print("Fixed " + str(count))
    print(str(strategy_stats))


main()
