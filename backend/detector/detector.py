"""
PII Detection Engine
====================
"""

import re
import json
import argparse

try:
    import spacy
    _nlp = spacy.load("en_core_web_sm")
    SPACY_AVAILABLE = True
except Exception:
    _nlp = None
    SPACY_AVAILABLE = False
    print("[WARNING] spaCy model not found.")

PATTERNS = {

    "email": re.compile(
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        re.IGNORECASE
    ),

    "phone": re.compile(
        r"(?<!\d)"
        r"(?:(?:\+91[\s\-]?)?[6-9]\d{9}|[6-9]\d{4}[\s]\d{5})"
        r"(?!\d)"
    ),

    "aadhaar": re.compile(
        r"(?<!\d)\d{4}[\s\-]?\d{4}[\s\-]?\d{4}(?!\d)"
    ),

    "pan": re.compile(
        r"(?<![A-Z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Z0-9:])"
    ),

    "ip_address": re.compile(
        r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?!\d)"
    ),

    # Card: exactly 4-4-4-4 groups with spaces/hyphens
    "card_number": re.compile(
        r"(?<!\d)\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}(?!\d)"
    ),

    "passport": re.compile(
        r"(?<![A-Z0-9])[A-Z]\d{7}(?![A-Z0-9])"
    ),

    "upi_id": re.compile(
        r"[a-zA-Z0-9.\-_+]+@[a-zA-Z]{3,}",
        re.IGNORECASE
    ),

    "ifsc": re.compile(
        r"(?<![A-Z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Z0-9])"
    ),

    "dob": re.compile(
        r"(?<!\d)(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{4}[\/\-\.]\d{1,2}[\/\-\.]\d{1,2})(?!\d)"
    ),

    "cvv": re.compile(
        r"(?:CVV|cvv|CVC|cvc)[\s:]*\d{3,4}",
        re.IGNORECASE
    ),

    "url": re.compile(
        r"https?://[^\s\"'<>]+",
        re.IGNORECASE
    ),

    "vehicle_reg": re.compile(
        r"(?<![A-Z0-9])[A-Z]{2}\d{2}[A-Z]{1,2}\d{4}(?![A-Z0-9])"
    ),

    "voter_id": re.compile(
        r"(?<![A-Z0-9])[A-Z]{3}\d{7}(?![A-Z0-9])"
    ),

    # Bank account: 9-18 digits NOT already matched as card (no spaces between groups)
    "bank_account": re.compile(
        r"(?<!\d)\d{9,18}(?!\d)"
    ),

    # Device ID: patterns like android-9f31acb8d1
    "device_id": re.compile(
        r"[a-zA-Z]+-[a-zA-Z0-9]{8,}"
    ),

    # Address: captures house number + full address up to pincode
    # Groups: group(1) = house number, group(2) = rest of address
    "address": re.compile(
        r"(\d{1,4})([\s,]+[A-Za-z0-9\s,\.\-]+"
        r"(?:Road|Street|Nagar|Society|Colony|Marg|Lane|Chowk|Area|Block|Sector|"
        r"Phase|Layout|Enclave|Vihar|Park|Place|Cross|Main|Residency|Apartments|"
        r"Flat|Floor|Building|Tower|Complex|Plaza|Garden|Gali|Mohalla)"
        r"[A-Za-z0-9\s,\.\-]*\d{6})",
        re.IGNORECASE
    ),
}


def _is_field_label(text: str, match_end: int) -> bool:
    lookahead = text[match_end: match_end + 2].strip()
    return lookahead.startswith(":")


_NOISE_WORDS = {
    "bank", "digital", "mobile", "phone", "email", "address",
    "card", "account", "number", "id", "code", "upi", "pan",
    "passport", "vehicle", "voter", "credit", "debit", "expiry",
    "date", "gender", "name", "nationality", "information", "details",
    "identifiers", "financial", "free", "text", "clean", "paragraph",
    "male", "female", "indian", "website", "linkedin", "device",
    "server", "alternate", "work", "home", "full", "end", "start",
}


def _is_noise_entity(val: str) -> bool:
    stripped = val.strip().lower()
    if len(stripped) <= 2:
        return True
    if stripped in _NOISE_WORDS:
        return True
    return False


class PIIDetector:

    def __init__(self, use_nlp: bool = True):
        self.use_nlp = use_nlp and SPACY_AVAILABLE
        self.patterns = PATTERNS

    def detect(self, text: str) -> dict:
        results = {}

        for pii_type, pattern in self.patterns.items():
            matches = []
            for m in pattern.finditer(text):
                if _is_field_label(text, m.end()):
                    continue
                matches.append(m.group().strip())

            seen = set()
            unique = []
            for m in matches:
                if m and m not in seen:
                    seen.add(m)
                    unique.append(m)
            if unique:
                results[pii_type] = unique

        if self.use_nlp and _nlp:
            doc = _nlp(text)
            names, orgs, locations = [], [], []

            for ent in doc.ents:
                val = ent.text.strip()
                if _is_field_label(text, ent.end_char):
                    continue
                if _is_noise_entity(val):
                    continue
                if ent.label_ == "PERSON" and val:
                    names.append(val)
                elif ent.label_ == "ORG" and val:
                    orgs.append(val)
                elif ent.label_ in ("GPE", "LOC") and val:
                    locations.append(val)

            if names:
                results["name"] = list(dict.fromkeys(names))
            if orgs:
                results["organisation"] = list(dict.fromkeys(orgs))
            if locations:
                results["location"] = list(dict.fromkeys(locations))

        return results

    def detect_with_positions(self, text: str) -> list:
        findings = []

        for pii_type, pattern in self.patterns.items():
            for m in pattern.finditer(text):
                if _is_field_label(text, m.end()):
                    continue

                # Address: store house number separately so sanitizer keeps it
                if pii_type == "address":
                    # group(1)=house number, group(2)=rest
                    # Keep house number visible, mask only the rest
                    rest_start = m.start(2)  # exact start of group 2
                    findings.append({
                        "type": "address",
                        "value": m.group(2),
                        "start": rest_start,
                        "end": m.end(),
                    })
                else:
                    findings.append({
                        "type": pii_type,
                        "value": m.group().strip(),
                        "start": m.start(),
                        "end": m.end(),
                    })

        if self.use_nlp and _nlp:
            doc = _nlp(text)
            label_map = {
                "PERSON": "name",
                "ORG": "organisation",
                "GPE": "location",
                "LOC": "location",
            }
            for ent in doc.ents:
                if ent.label_ in label_map:
                    if _is_field_label(text, ent.end_char):
                        continue
                    if _is_noise_entity(ent.text):
                        continue
                    findings.append({
                        "type": label_map[ent.label_],
                        "value": ent.text.strip(),
                        "start": ent.start_char,
                        "end": ent.end_char,
                    })

        findings.sort(key=lambda x: x["start"])
        return findings

    def has_pii(self, text: str) -> bool:
        return bool(self.detect(text))

    def summary(self, text: str) -> dict:
        results = self.detect(text)
        counts = {k: len(v) for k, v in results.items()}
        total = sum(counts.values())
        return {
            "detected": results,
            "counts": counts,
            "total_pii_found": total,
        }


def _cli():
    parser = argparse.ArgumentParser(description="PII Detection Engine")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--text", type=str)
    group.add_argument("--file", type=str)
    parser.add_argument("--output", type=str, default=None)
    parser.add_argument("--no-nlp", action="store_true")
    parser.add_argument("--positions", action="store_true")
    args = parser.parse_args()

    if args.text:
        text = args.text
    else:
        with open(args.file, "r", encoding="utf-8") as f:
            text = f.read()

    detector = PIIDetector(use_nlp=not args.no_nlp)
    results = detector.detect_with_positions(text) if args.positions else detector.summary(text)

    output_json = json.dumps(results, indent=2, ensure_ascii=False)
    print("\n══════════════ PII DETECTION RESULTS ══════════════")
    print(output_json)
    print("════════════════════════════════════════════════════\n")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output_json)
        print(f"[✓] Results saved to: {args.output}")


if __name__ == "__main__":
    _cli()