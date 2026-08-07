"""
Labelled evaluation cases for all five tools.

These are held deliberately separate from the unit tests. Unit tests assert that
a specific mechanism works; these cases measure *accuracy* — how often each tool
reaches the right verdict on realistic input, including input designed to be
tempting false positives.

Every case is labelled by hand from real-world patterns (Indian recruitment
scams, real resume layouts, real security-header configurations). Cases the
tools already pass are included on purpose: an evaluation set that only contains
known failures cannot show a regression.
"""

# ---------------------------------------------------------------------------
# LinkGuard — (url, should_be_flagged, note)
# A URL is "flagged" when its verdict is SUSPICIOUS or DANGEROUS.
# ---------------------------------------------------------------------------
LINKGUARD_CASES = [
    # --- genuinely malicious -------------------------------------------------
    ("https://jmdcaremaker.com/login", True, "typosquat: dropped a letter"),
    ("https://jmdcareermakers.com/apply", True, "typosquat: plural"),
    ("https://jmdcareermaker.com.secure-login.ru/verify", True, "brand buried in subdomain"),
    ("http://jmdcareermaker.com@192.168.0.5/pay?token=abc", True, "userinfo credential trap"),
    ("https://xn--jmdcareermker-9zb.com/account", True, "punycode homograph"),
    ("http://bit.ly/jmd-offer", True, "shortener hides destination"),
    ("http://203.0.113.44/careers/offer.html", True, "raw IP host"),
    ("https://jmd-career-maker-verify.xyz/kyc", True, "lookalike + throwaway TLD"),
    ("https://jmdcareermaker.freehosting.tk/login", True, "brand as subdomain of free host"),
    ("http://secure-jmdcareermaker.com/update-password", True, "brand embedded in other domain"),
    ("https://jmdcareermaker.com.verify-account.top/signin", True, "brand + suspicious TLD"),
    ("http://192.168.1.10:8080/offer", True, "IP + non-standard port"),
    ("javascript:alert(document.cookie)", True, "script pseudo-scheme"),
    ("data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", True, "data URI payload"),
    ("https://jmdcareermaker.com.evil.ru/offer-letter.pdf.exe", True, "double extension executable"),
    ("https://jmdcаreermaker.com/login", True, "Cyrillic homoglyph, not punycode"),

    # --- genuinely benign — these must NOT be flagged -------------------------
    ("https://jmdcareermaker.com/careers/ai-cybersecurity-intern", False, "official careers page"),
    ("https://jmdcareermaker.com/login", False, "official login page — sensitive word is expected"),
    ("https://jmdcareermaker.com/account/settings", False, "official account page"),
    ("jmdcareermaker.com/careers", False, "official domain, scheme simply omitted when pasted"),
    ("https://www.jmdcareermaker.com/offer-letter/12345", False, "official offer letter"),
    ("https://www.linkedin.com/jobs/view/4012345678", False, "LinkedIn job posting"),
    ("https://in.indeed.com/viewjob?jk=abc123", False, "Indeed job posting"),
    ("https://www.naukri.com/job-listings-security-analyst", False, "Naukri listing"),
    ("https://github.com/kakarot6911/jmd-ai-security-suite", False, "GitHub repo"),
    ("https://docs.google.com/forms/d/e/1FAIpQLSf/viewform", False, "Google Form application"),
    ("https://careers.microsoft.com/us/en/job/1234567/Security-Analyst", False, "corporate careers page"),
    ("https://www.accounting-firm.co.in/about", False, "'account' substring inside a real word"),
    ("https://news.ycombinator.com/item?id=12345", False, "ordinary link"),
    ("https://company.com/updates/2026-newsletter", False, "'update' substring in a real word"),
    ("https://zoom.us/j/9876543210?pwd=abcdef", False, "legit meeting link with pwd param"),
]

# ---------------------------------------------------------------------------
# ResumeShield — (text, expected_types_present, expected_types_absent, note)
# ---------------------------------------------------------------------------
RESUMESHIELD_CASES = [
    # --- must detect ---------------------------------------------------------
    ("Aadhaar: 2994 1855 6015", {"AADHAAR"}, set(), "valid Aadhaar (Verhoeff)"),
    ("PAN: ABCDE1234F", {"PAN"}, set(), "PAN"),
    ("Email: fazal.ahmad@example.com", {"EMAIL"}, set(), "email"),
    ("Phone: +91 98765 43210", {"PHONE"}, set(), "Indian mobile"),
    ("Card 4111 1111 1111 1111", {"CREDIT_CARD"}, set(), "Luhn-valid Visa test number"),
    ("A/c 123456789012 (HDFC Bank)", {"BANK_ACCOUNT"}, set(), "account with context"),
    ("DOB: 23/08/2001", {"DOB"}, set(), "labelled date of birth"),
    ("IFSC: HDFC0001234", {"IFSC"}, set(), "bank IFSC code"),
    ("UAN: 101234567890", {"UAN"}, set(), "provident-fund UAN"),
    ("Voter ID: ABC1234567", {"VOTER_ID"}, set(), "EPIC voter number"),
    ("UPI: fazal@okhdfcbank", {"UPI_ID"}, set(), "UPI handle"),
    ("DL No: MH12 20110012345", {"DRIVING_LICENCE"}, set(), "driving licence"),
    ("Address: Tower 28, Lodha Belmondo, Pune 411045", {"PIN_CODE"}, set(), "PIN in an address"),
    ("Date of Birth: 23 August 2001", {"DOB"}, set(), "spelled-out DOB"),

    # --- must NOT detect (false-positive traps) ------------------------------
    ("Expected CTC: 500000 per annum", set(), {"PIN_CODE"}, "salary is not a PIN code"),
    ("Scored 987654 points in the competition", set(), {"PIN_CODE"}, "score is not a PIN code"),
    ("Graduated 2019, GPA 8.5, 240000 lines of code reviewed", set(), {"PIN_CODE"}, "counts are not PINs"),
    ("Employee ID: B2345678 at Acme Corp", set(), {"PASSPORT"}, "employee ID is not a passport"),
    ("Reference SKU A1234567 for the inventory project", set(), {"PASSPORT"}, "SKU is not a passport"),
    ("Aadhaar: 1234 5678 9012", set(), {"AADHAAR"}, "invalid checksum must be rejected"),
    ("Order total 4111 1111 1111 1112", set(), {"CREDIT_CARD"}, "Luhn-invalid must be rejected"),
    ("Managed a budget of 750000 INR", set(), {"PIN_CODE"}, "budget is not a PIN code"),
    ("Project ran from 2018 to 2022 across 400000 users", set(), {"PIN_CODE"}, "user count is not a PIN"),
]

# ---------------------------------------------------------------------------
# PhishGuard — (text, sender, company, is_scam, note)
# ---------------------------------------------------------------------------
PHISHGUARD_CASES = [
    # --- scams ---------------------------------------------------------------
    ("Congratulations! You are SELECTED without any interview. Pay a refundable "
     "registration fee of Rs. 1,999 today. Limited slots! http://bit.ly/jmd-offer",
     "jmd.careers.official@gmail.com", "JMD The Career Maker", True, "fee + no interview + shortener"),
    ("Dear Candidate, your profile is shortlisted for a work from home job. "
     "Earn up to 45,000 per month with daily payout. No experience required. "
     "Contact us on WhatsApp +919812345678.",
     "hr.recruitment2026@gmail.com", "JMD The Career Maker", True, "WFH payout scam"),
    ("Your offer letter is ready. To process document verification, deposit Rs 2500 "
     "security fee to the account below. Reply within 24 hours or the offer expires.",
     "offers@jmd-careermaker.co", "JMD The Career Maker", True, "deposit + urgency + lookalike domain"),
    ("Please share your Aadhaar number, PAN card details and net banking password "
     "to complete onboarding formalities.",
     "onboarding@jmdcareers-verify.tk", "JMD The Career Maker", True, "credential harvesting"),
    ("You have been directly selected. Purchase the training kit worth Rs 3,499 "
     "which will be reimbursed with your first salary.",
     "training@gmail.com", "JMD The Career Maker", True, "pay for equipment"),
    ("URGENT: Claim your job offer by sending a Google Play card worth Rs 2000 "
     "to the HR manager immediately.",
     "hrmanager.jmd@yahoo.com", "JMD The Career Maker", True, "gift card scam"),

    # --- legitimate — these must NOT be flagged as scams ---------------------
    ("Dear Fazal Ahmad, thank you for applying to the AI Cybersecurity Intern position "
     "at JMD The Career Maker. We would like to invite you to a virtual interview on "
     "Tuesday. No fee is required at any stage of our process.",
     "akash.mishra@jmdcareermaker.com", "JMD The Career Maker", False, "genuine interview invite"),
    ("Hi Fazal, following your interview, we are pleased to offer you the Security Analyst "
     "role. The annual compensation is Rs 12 LPA. Please review the attached offer letter "
     "and revert with your acceptance.",
     "hr@jmdcareermaker.com", "JMD The Career Maker", False, "genuine offer stating salary"),
    ("Hello, we pay 8 LPA for this position and the notice period is 30 days. "
     "Could you confirm whether that works before we proceed to the final round?",
     "recruiter@jmdcareermaker.com", "JMD The Career Maker", False,
     "'we pay <number>' is a salary, not a demand for payment"),
    ("Dear Fazal, please complete the background verification form at "
     "https://jmdcareermaker.com/verify before your joining date. "
     "Reach out to me immediately if you have questions.",
     "hr@jmdcareermaker.com", "JMD The Career Maker", False,
     "'immediately' in a normal sentence is not urgency pressure"),
    ("Thank you for your application. Unfortunately we are not moving forward at this "
     "time, but we will keep your profile on file for future openings.",
     "careers@jmdcareermaker.com", "JMD The Career Maker", False, "rejection email"),
    ("Your interview with the engineering panel is confirmed for 10:00 AM. "
     "The meeting link is https://zoom.us/j/9876543210. Please join five minutes early.",
     "scheduling@jmdcareermaker.com", "JMD The Career Maker", False, "interview scheduling"),
    ("Hi, I'm a freelance recruiter working with several startups. Are you open to a "
     "backend role in Pune? Happy to share the JD if you're interested.",
     "priya.recruits@gmail.com", "", False,
     "independent recruiter on gmail with no company claim — not automatically a scam"),
]

# ---------------------------------------------------------------------------
# SiteGuard — (headers, scheme, expected_min_grade, expected_max_grade, note)
# Grades are ordered F < D < C < B < A.
# ---------------------------------------------------------------------------
HARDENED_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), camera=()",
}

# (headers, scheme, finding_ids_that_must_fire, finding_ids_that_must_not_fire, note)
# Asserting on findings rather than the letter grade measures detection directly:
# a grade band can hide both a miss and a spurious hit behind the same letter.
ALL_MISSING = {
    "hdr-missing-strict-transport-security", "hdr-missing-content-security-policy",
    "hdr-missing-x-frame-options", "hdr-missing-x-content-type-options",
    "hdr-missing-referrer-policy", "hdr-missing-permissions-policy",
}

SITEGUARD_CASES = [
    (HARDENED_HEADERS, "https", set(), ALL_MISSING | {"csp-weak", "hsts-weak", "xfo-invalid"},
     "fully hardened site must produce no findings"),
    ({}, "https", ALL_MISSING, set(), "bare site must flag every missing header"),
    ({**HARDENED_HEADERS, "Server": "nginx"}, "https", set(), {"banner-server"},
     "generic banner with no version is not an actionable leak"),
    ({**HARDENED_HEADERS, "Server": "Apache/2.4.29 (Ubuntu)"}, "https", {"banner-server"}, set(),
     "versioned banner IS a real leak"),
    ({**HARDENED_HEADERS, "X-Powered-By": "PHP/7.4.3"}, "https", {"banner-x-powered-by"}, set(),
     "versioned x-powered-by is a leak"),
    ({**HARDENED_HEADERS, "Content-Security-Policy": "default-src *; script-src 'unsafe-inline' *"},
     "https", {"csp-weak"}, {"hdr-missing-content-security-policy"},
     "a permissive CSP must not count as protection"),
    ({**HARDENED_HEADERS, "Content-Security-Policy": "default-src 'self'; img-src data:"},
     "https", {"csp-weak"}, set(), "data: source weakens the policy"),
    ({**HARDENED_HEADERS, "Strict-Transport-Security": "max-age=0"}, "https", {"hsts-weak"}, set(),
     "max-age=0 disables HSTS entirely"),
    ({**HARDENED_HEADERS, "Strict-Transport-Security": "max-age=300"}, "https", {"hsts-weak"}, set(),
     "a 5-minute max-age is effectively no HSTS"),
    ({**HARDENED_HEADERS, "X-Frame-Options": "ALLOWALL"}, "https", {"xfo-invalid"}, set(),
     "ALLOWALL is ignored by browsers"),
    ({**HARDENED_HEADERS, "X-Frame-Options": "SAMEORIGIN"}, "https", set(), {"xfo-invalid"},
     "SAMEORIGIN is valid"),
    ({**HARDENED_HEADERS, "Set-Cookie": "sid=abc; Path=/"}, "https", {"cookie-flags"}, set(),
     "cookie missing Secure/HttpOnly/SameSite"),
    ({**HARDENED_HEADERS, "Set-Cookie": "sid=abc; Secure; HttpOnly; SameSite=Lax"},
     "https", set(), {"cookie-flags"}, "correctly flagged cookie is fine"),
    ({k: v for k, v in HARDENED_HEADERS.items() if k != "Strict-Transport-Security"},
     "http", set(), {"hdr-missing-strict-transport-security"},
     "HSTS is meaningless over plain http and must not be demanded"),
]

# ---------------------------------------------------------------------------
# BreachRadar — structural correctness of scoring
# ---------------------------------------------------------------------------
BREACHRADAR_INVARIANTS = [
    "no duplicate breach entries in a single account's result",
    "risk scores must discriminate (not all saturate at 100)",
    "an account in more/severe breaches must not score below a lesser-exposed one",
]
