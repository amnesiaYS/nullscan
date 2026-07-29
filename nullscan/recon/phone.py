"""Phone number validation and basic metadata.

Pure-logic implementation: no external libraries, no carrier lookup APIs.
Detects country code, validates length, normalizes to E.164, suggests
formatting fixes.
"""

from __future__ import annotations

import re
from typing import Any

from rich.console import Console

from ..output import print_kv_panel, print_status

# Country metadata: code, name, expected length(s) (without country code),
# optional national prefix.
COUNTRIES: dict[str, dict[str, Any]] = {
    "1":   {"name": "US/Canada",            "lengths": [10],                "trunk": "1"},
    "7":   {"name": "Russia/Kazakhstan",    "lengths": [10],                "trunk": "8"},
    "20":  {"name": "Egypt",                "lengths": [10],                "trunk": "0"},
    "27":  {"name": "South Africa",         "lengths": [9],                 "trunk": "0"},
    "30":  {"name": "Greece",               "lengths": [10],                "trunk": "0"},
    "31":  {"name": "Netherlands",          "lengths": [9],                 "trunk": "0"},
    "32":  {"name": "Belgium",              "lengths": [9],                 "trunk": "0"},
    "33":  {"name": "France",               "lengths": [9],                 "trunk": "0"},
    "34":  {"name": "Spain",                "lengths": [9],                 "trunk": "9"},
    "39":  {"name": "Italy",                "lengths": [6, 7, 8, 9, 10, 11], "trunk": "0"},
    "40":  {"name": "Romania",              "lengths": [9],                 "trunk": "0"},
    "41":  {"name": "Switzerland",          "lengths": [9],                 "trunk": "0"},
    "43":  {"name": "Austria",              "lengths": [10],                "trunk": "0"},
    "44":  {"name": "United Kingdom",       "lengths": [10],                "trunk": "0"},
    "45":  {"name": "Denmark",              "lengths": [8],                 "trunk": "9"},
    "46":  {"name": "Sweden",               "lengths": [9],                 "trunk": "0"},
    "47":  {"name": "Norway",               "lengths": [8],                 "trunk": "9"},
    "48":  {"name": "Poland",               "lengths": [9],                 "trunk": "0"},
    "49":  {"name": "Germany",              "lengths": [10, 11],            "trunk": "0"},
    "51":  {"name": "Peru",                 "lengths": [9],                 "trunk": "0"},
    "52":  {"name": "Mexico",               "lengths": [10, 11],            "trunk": "0"},
    "54":  {"name": "Argentina",            "lengths": [10],                "trunk": "0"},
    "55":  {"name": "Brazil",               "lengths": [10, 11],            "trunk": "0"},
    "56":  {"name": "Chile",                "lengths": [9],                 "trunk": "0"},
    "57":  {"name": "Colombia",             "lengths": [10],                "trunk": "0"},
    "60":  {"name": "Malaysia",             "lengths": [9, 10],             "trunk": "0"},
    "61":  {"name": "Australia",            "lengths": [9],                 "trunk": "0"},
    "62":  {"name": "Indonesia",            "lengths": [9, 10, 11],         "trunk": "0"},
    "63":  {"name": "Philippines",          "lengths": [10],                "trunk": "0"},
    "64":  {"name": "New Zealand",          "lengths": [9, 10],             "trunk": "0"},
    "65":  {"name": "Singapore",            "lengths": [8],                 "trunk": "9"},
    "66":  {"name": "Thailand",             "lengths": [9],                 "trunk": "0"},
    "81":  {"name": "Japan",                "lengths": [10],                "trunk": "0"},
    "82":  {"name": "South Korea",          "lengths": [9, 10],             "trunk": "0"},
    "84":  {"name": "Vietnam",              "lengths": [9, 10],             "trunk": "0"},
    "86":  {"name": "China",                "lengths": [11],                "trunk": "0"},
    "90":  {"name": "Turkey",               "lengths": [10],                "trunk": "0"},
    "91":  {"name": "India",                "lengths": [10],                "trunk": "0"},
    "92":  {"name": "Pakistan",             "lengths": [10],                "trunk": "0"},
    "93":  {"name": "Afghanistan",          "lengths": [9],                 "trunk": "0"},
    "94":  {"name": "Sri Lanka",            "lengths": [9],                 "trunk": "0"},
    "95":  {"name": "Myanmar",              "lengths": [9],                 "trunk": "0"},
    "98":  {"name": "Iran",                 "lengths": [10],                "trunk": "0"},
    "211": {"name": "South Sudan",          "lengths": [9],                 "trunk": "0"},
    "212": {"name": "Morocco",              "lengths": [9],                 "trunk": "0"},
    "213": {"name": "Algeria",              "lengths": [9],                 "trunk": "0"},
    "216": {"name": "Tunisia",              "lengths": [8],                 "trunk": "0"},
    "218": {"name": "Libya",                "lengths": [9],                 "trunk": "0"},
    "220": {"name": "Gambia",               "lengths": [7],                 "trunk": "0"},
    "221": {"name": "Senegal",              "lengths": [9],                 "trunk": "0"},
    "234": {"name": "Nigeria",              "lengths": [10],                "trunk": "0"},
    "250": {"name": "Rwanda",               "lengths": [9],                 "trunk": "0"},
    "251": {"name": "Ethiopia",             "lengths": [9],                 "trunk": "0"},
    "254": {"name": "Kenya",                "lengths": [9],                 "trunk": "0"},
    "255": {"name": "Tanzania",             "lengths": [9],                 "trunk": "0"},
    "256": {"name": "Uganda",               "lengths": [9],                 "trunk": "0"},
    "260": {"name": "Zambia",               "lengths": [9],                 "trunk": "0"},
    "263": {"name": "Zimbabwe",             "lengths": [9],                 "trunk": "0"},
    "351": {"name": "Portugal",             "lengths": [9],                 "trunk": "0"},
    "352": {"name": "Luxembourg",           "lengths": [9],                 "trunk": "0"},
    "353": {"name": "Ireland",              "lengths": [9],                 "trunk": "0"},
    "354": {"name": "Iceland",              "lengths": [7],                 "trunk": "0"},
    "355": {"name": "Albania",              "lengths": [9],                 "trunk": "0"},
    "356": {"name": "Malta",                "lengths": [8],                 "trunk": "0"},
    "357": {"name": "Cyprus",               "lengths": [8],                 "trunk": "0"},
    "358": {"name": "Finland",              "lengths": [9],                 "trunk": "0"},
    "359": {"name": "Bulgaria",             "lengths": [9],                 "trunk": "0"},
    "370": {"name": "Lithuania",            "lengths": [8],                 "trunk": "0"},
    "371": {"name": "Latvia",               "lengths": [8],                 "trunk": "0"},
    "372": {"name": "Estonia",              "lengths": [8],                 "trunk": "0"},
    "373": {"name": "Moldova",              "lengths": [8],                 "trunk": "0"},
    "374": {"name": "Armenia",              "lengths": [8],                 "trunk": "0"},
    "375": {"name": "Belarus",              "lengths": [9],                 "trunk": "0"},
    "376": {"name": "Andorra",              "lengths": [6],                 "trunk": "0"},
    "377": {"name": "Monaco",               "lengths": [8],                 "trunk": "0"},
    "378": {"name": "San Marino",           "lengths": [9],                 "trunk": "0"},
    "380": {"name": "Ukraine",              "lengths": [9],                 "trunk": "0"},
    "381": {"name": "Serbia",               "lengths": [9],                 "trunk": "0"},
    "382": {"name": "Montenegro",           "lengths": [8],                 "trunk": "0"},
    "383": {"name": "Kosovo",               "lengths": [8],                 "trunk": "0"},
    "385": {"name": "Croatia",              "lengths": [9],                 "trunk": "0"},
    "386": {"name": "Slovenia",             "lengths": [8],                 "trunk": "0"},
    "387": {"name": "Bosnia and Herzegovina","lengths": [8],                "trunk": "0"},
    "389": {"name": "North Macedonia",      "lengths": [8],                 "trunk": "0"},
    "420": {"name": "Czech Republic",        "lengths": [9],                "trunk": "0"},
    "421": {"name": "Slovakia",              "lengths": [9],                "trunk": "0"},
    "423": {"name": "Liechtenstein",         "lengths": [7],                "trunk": "0"},
    "500": {"name": "Falkland Islands",      "lengths": [5],                "trunk": "0"},
    "501": {"name": "Belize",                "lengths": [7],                "trunk": "0"},
    "502": {"name": "Guatemala",             "lengths": [8],                "trunk": "0"},
    "503": {"name": "El Salvador",           "lengths": [8],                "trunk": "0"},
    "504": {"name": "Honduras",              "lengths": [8],                "trunk": "0"},
    "505": {"name": "Nicaragua",             "lengths": [8],                "trunk": "0"},
    "506": {"name": "Costa Rica",            "lengths": [8],                "trunk": "0"},
    "507": {"name": "Panama",                "lengths": [8],                "trunk": "0"},
    "509": {"name": "Haiti",                 "lengths": [8],                "trunk": "0"},
    "591": {"name": "Bolivia",               "lengths": [8],                "trunk": "0"},
    "592": {"name": "Guyana",                "lengths": [7],                "trunk": "0"},
    "593": {"name": "Ecuador",               "lengths": [9],                "trunk": "0"},
    "595": {"name": "Paraguay",              "lengths": [9],                "trunk": "0"},
    "598": {"name": "Uruguay",               "lengths": [8],                "trunk": "0"},
    "599": {"name": "Curaçao/Netherlands Antilles","lengths": [7, 8],         "trunk": "0"},
    "670": {"name": "Timor-Leste",           "lengths": [8],                "trunk": "0"},
    "672": {"name": "Norfolk Island",        "lengths": [5],                "trunk": "0"},
    "673": {"name": "Brunei",                "lengths": [7],                "trunk": "0"},
    "674": {"name": "Nauru",                 "lengths": [7],                "trunk": "0"},
    "675": {"name": "Papua New Guinea",      "lengths": [8],                "trunk": "0"},
    "676": {"name": "Tonga",                 "lengths": [5],                "trunk": "0"},
    "677": {"name": "Solomon Islands",       "lengths": [5],                "trunk": "0"},
    "678": {"name": "Vanuatu",               "lengths": [5],                "trunk": "0"},
    "679": {"name": "Fiji",                  "lengths": [7],                "trunk": "0"},
    "680": {"name": "Palau",                 "lengths": [7],                "trunk": "0"},
    "682": {"name": "Cook Islands",          "lengths": [5],                "trunk": "0"},
    "685": {"name": "Samoa",                 "lengths": [5],                "trunk": "0"},
    "686": {"name": "Kiribati",              "lengths": [5],                "trunk": "0"},
    "687": {"name": "New Caledonia",         "lengths": [6],                "trunk": "0"},
    "688": {"name": "Tuvalu",                "lengths": [5],                "trunk": "0"},
    "689": {"name": "French Polynesia",      "lengths": [6],                "trunk": "0"},
    "691": {"name": "Micronesia",            "lengths": [7],                "trunk": "0"},
    "692": {"name": "Marshall Islands",      "lengths": [7],                "trunk": "0"},
    "850": {"name": "North Korea",           "lengths": [10],               "trunk": "0"},
    "852": {"name": "Hong Kong",             "lengths": [8],                "trunk": "0"},
    "853": {"name": "Macau",                 "lengths": [8],                "trunk": "0"},
    "855": {"name": "Cambodia",              "lengths": [9],                "trunk": "0"},
    "856": {"name": "Laos",                  "lengths": [10],               "trunk": "0"},
    "880": {"name": "Bangladesh",            "lengths": [10],               "trunk": "0"},
    "886": {"name": "Taiwan",                "lengths": [9],                "trunk": "0"},
    "960": {"name": "Maldives",              "lengths": [7],                "trunk": "0"},
    "961": {"name": "Lebanon",               "lengths": [8],                "trunk": "0"},
    "962": {"name": "Jordan",                "lengths": [9],                "trunk": "0"},
    "963": {"name": "Syria",                 "lengths": [9],                "trunk": "0"},
    "964": {"name": "Iraq",                  "lengths": [10],               "trunk": "0"},
    "965": {"name": "Kuwait",                "lengths": [8],                "trunk": "0"},
    "966": {"name": "Saudi Arabia",          "lengths": [9],                "trunk": "0"},
    "967": {"name": "Yemen",                 "lengths": [9],                "trunk": "0"},
    "968": {"name": "Oman",                  "lengths": [8],                "trunk": "0"},
    "970": {"name": "Palestine",             "lengths": [9],                "trunk": "0"},
    "971": {"name": "United Arab Emirates",  "lengths": [9],                "trunk": "0"},
    "972": {"name": "Israel",                "lengths": [9],                "trunk": "0"},
    "973": {"name": "Bahrain",               "lengths": [8],                "trunk": "0"},
    "974": {"name": "Qatar",                 "lengths": [8],                "trunk": "0"},
    "975": {"name": "Bhutan",                "lengths": [8],                "trunk": "0"},
    "976": {"name": "Mongolia",              "lengths": [8],                "trunk": "0"},
    "977": {"name": "Nepal",                 "lengths": [10],               "trunk": "0"},
    "992": {"name": "Tajikistan",            "lengths": [9],                "trunk": "8"},
    "993": {"name": "Turkmenistan",          "lengths": [8],                "trunk": "8"},
    "994": {"name": "Azerbaijan",            "lengths": [9],                "trunk": "8"},
    "995": {"name": "Georgia",               "lengths": [9],                "trunk": "8"},
    "996": {"name": "Kyrgyzstan",            "lengths": [9],                "trunk": "8"},
    "998": {"name": "Uzbekistan",            "lengths": [9],                "trunk": "8"},
}


def _strip(raw: str) -> str:
    """Remove everything except digits and a leading +."""
    s = raw.strip()
    plus = ""
    if s.startswith("+"):
        plus = "+"
    return plus + re.sub(r"\D", "", s)


def _detect_country(e164: str) -> tuple[str, dict[str, Any]] | None:
    """Find the longest matching country code prefix."""
    digits = e164.lstrip("+")
    for length in (3, 2, 1):
        prefix = digits[:length]
        if prefix in COUNTRIES:
            return prefix, COUNTRIES[prefix]
    return None


def parse(raw: str) -> dict[str, Any]:
    """Parse a single phone number into structured info."""
    e164 = _strip(raw)
    if not e164 or not e164.lstrip("+").isdigit():
        return {"input": raw, "valid": False, "error": "no digits found"}

    detected = _detect_country(e164)
    if not detected:
        return {
            "input": raw,
            "normalized": e164,
            "valid": False,
            "country_code": None,
            "country_name": None,
            "error": "unknown or missing country code (prefix the number with +XX)",
        }

    code, info = detected
    digits = e164.lstrip("+")
    national = digits[len(code):]
    expected_lengths = info["lengths"]

    # Italy (and some others) accept numbers with or without trunk prefix.
    if code == "39" and national.startswith(info["trunk"]):
        national = national[1:]

    valid_length = len(national) in expected_lengths

    result = {
        "input": raw,
        "normalized": f"+{digits}",
        "valid": bool(valid_length),
        "country_code": code,
        "country_name": info["name"],
        "national_number": national,
        "national_length": len(national),
        "expected_lengths": expected_lengths,
        "trunk_prefix": info["trunk"],
        "error": None if valid_length else f"length {len(national)} not in expected {expected_lengths}",
    }
    return result


def scan(targets: list[str]) -> dict[str, Any]:
    """Parse one or more phone numbers."""
    results = [parse(t) for t in targets]
    valid = sum(1 for r in results if r.get("valid"))
    return {"count": len(results), "valid": valid, "results": results}


def render(data: dict[str, Any], console: Console) -> None:
    if not data.get("results"):
        print_status(console, "info", "no phone numbers provided")
        return

    print_status(
        console,
        "ok" if data.get("valid", 0) == data.get("count", 0) else "warn",
        f"{data['valid']}/{data['count']} phone numbers parsed",
    )

    for r in data["results"]:
        if r.get("error") and not r.get("country_code"):
            print_status(console, "bad", f"{r['input']}: {r['error']}")
            continue

        kind = "ok" if r.get("valid") else "warn"
        console.print(
            f"[status.{kind}]{'[+]' if kind == 'ok' else '[!]'}[/status.{kind}] "
            f"[primary]{r['normalized']}[/primary]  "
            f"[accent]{r.get('country_name', '?')}[/accent]"
            f"  [muted]({r['country_code']}, national {r['national_length']} digits)[/muted]"
        )
        if not r.get("valid"):
            print_status(console, "warn", f"  expected lengths: {r['expected_lengths']}")