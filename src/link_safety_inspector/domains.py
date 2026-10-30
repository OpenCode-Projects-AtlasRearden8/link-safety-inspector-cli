TWO_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "co.jp", "co.nz", "co.in", "co.za", "co.kr", "co.il",
    "com.au", "com.br", "com.cn", "com.mx", "com.ar", "com.tr",
    "com.sg", "com.hk", "net.au", "net.cn", "org.nz", "org.cn",
    "github.io", "gitlab.io", "pages.dev", "web.app", "vercel.app",
    "netlify.app", "fly.dev", "workers.dev", "blogspot.com",
    "appspot.com", "wordpress.com", "herokuapp.com", "sourceforge.net",
}

TRUSTED_BRANDS = {
    "paypal.com",
    "google.com", "gmail.com", "accounts.google.com",
    "microsoft.com", "office.com", "outlook.com", "live.com",
    "apple.com", "icloud.com",
    "amazon.com",
    "netflix.com",
    "facebook.com", "instagram.com", "whatsapp.com",
    "x.com", "twitter.com",
    "linkedin.com",
    "github.com",
    "yahoo.com", "aol.com", "hotmail.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com",
    "citibank.com", "capitalone.com", "americanexpress.com",
    "santanderbank.com", "usbank.com", "discover.com",
    "coinbase.com", "binance.com", "robinhood.com",
    "venmo.com", "zellepay.com", "cash.app",
    "ebay.com", "etsy.com",
    "walmart.com", "target.com",
    "fedex.com", "ups.com", "usps.com", "dhl.com",
    "irs.gov", "ssa.gov",
    "turbotax.com", "docusign.com", "dropbox.com",
    "zoom.us", "spotify.com", "adobe.com",
    "verizon.com", "att.com", "t-mobile.com", "xfinity.com",
}

CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ҝ": "k", "ҭ": "t",
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "ν": "v", "υ": "u", "κ": "k",
    "ι": "i", "τ": "t", "ϳ": "j",
    "ı": "i", "0": "o", "1": "l", "3": "e", "5": "s", "4": "a",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "s.id",
    "rb.gy", "tiny.cc", "bit.do", "qr.ae", "shorte.st", "soo.gd",
    "clk.sh", "shrtco.de", "tr.ee", "lnkd.in", "su.pr",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".msi", ".apk", ".bat", ".cmd", ".com",
    ".pif", ".vbs", ".ps1", ".jar", ".dmg",
}

CREDENTIAL_WORDS = (
    "login", "log-in", "logon", "signin", "sign-in", "signon",
    "verify", "verification", "confirm", "secure", "security",
    "password", "passwd", "passcode", "unlock", "recover",
    "account", "myaccount", "update-account", "billing", "invoice",
    "payment", "refund", "suspended", "limited", "alert",
    "authenticate", "session", "webscr", "reset", "2fa",
    "one-time", "otp", "token", "support-case", "case-id",
)

ABUSED_TLDS = {
    "top", "xyz", "tk", "ml", "ga", "cf", "gq", "su", "ru",
    "icu", "click", "rest", "cyou", "cam", "quest", "monster",
}

REDIRECT_PARAMS = (
    "url", "u", "next", "redirect", "redirect_url", "redirect_uri",
    "goto", "go", "target", "link", "dest", "destination", "continue",
    "return", "return_to", "r", "out", "outgoing", "track", "click",
    "forward", "follow", "site", "to",
)
