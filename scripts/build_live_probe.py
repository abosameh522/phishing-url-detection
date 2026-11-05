"""Build tests/live_probe_urls.csv — the live API regression probe set.

Frozen BEFORE the v3 retrain (2026-11-05, per the task spec). It is never used in
training, validation, calibration, or threshold selection; it is only scored through the
API code path by gates.py (G6) and reported manually.

Composition (per spec):
  - 80 legitimate: 40 bare popular domains + 40 with paths/queries on popular sites
    and hosted platforms (docs/drive/workflow-style deep paths included).
  - 30 phishing-pattern strings on reserved/example-style fake domains, plus private-IP
    constructions. Strings only; nothing is ever fetched or resolved.
"""
import csv

bare = [
    "https://www.google.com/", "github.com", "amazon.com", "wikipedia.org",
    "youtube.com", "microsoft.com", "apple.com", "reddit.com",
    "https://python.org/", "https://www.netflix.com/", "mansoura.edu.eg",
    "https://open.spotify.com/", "https://www.booking.com/", "www.chase.com",
    "https://www.ebay.com/", "https://www.linkedin.com/", "medium.com",
    "https://www.dropbox.com/", "https://zoom.us/", "https://www.notion.so/",
    "https://trello.com/", "https://www.figma.com/", "cloudflare.com",
    "https://www.instagram.com/", "https://www.facebook.com/",
    "https://www.wellsfargo.com/", "https://www.citibank.de/",
    "https://www.web.de/", "https://mail.ru/", "https://www.bestbuy.com/",
    "https://www.target.com/", "https://www.homedepot.com/",
    "https://www.walmart.com/", "https://www.etsy.com/", "https://www.live.com/",
    "https://www.office.com/", "https://outlook.com/", "https://www.twitch.tv/",
    "https://www.booking.nl/", "https://www.ouedkniss.com/",
]

pathed = [
    "https://github.com/psf/requests/issues/6851",
    "https://github.com/psf/requests/issues?q=is%3Apr+sort%3Aupdated-desc",
    "https://www.amazon.com/s?k=coffee+beans&ref=nb_sb_noss_1",
    "https://www.amazon.com/dp/B08N5WRWNW?ref_=cs_503_link",
    "https://stackoverflow.com/questions/11227809/why-is-processing-a-sorted-array-faster",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Main_Page#section",
    "https://www.reddit.com/r/aww/top/?sort=top&t=all",
    "https://www.python.org/downloads/source/",
    "https://docs.python.org/3/library/stdtypes.html",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.youtube.com/feed/subscriptions",
    "https://www.microsoft.com/en-us/windows/windows-11",
    "https://support.apple.com/en-us/HT204053",
    "https://www.paypal.com/us/smarthelp/home",
    "https://www.booking.com/hotel/us/marriott-marquis.html",
    "https://outlook.office.com/mail/inbox/",
    "https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz/edit",
    "https://docs.google.com/spreadsheets/d/1abc123/edit#gid=0",
    "https://drive.google.com/file/d/1abc123/view?usp=sharing",
    "https://www.linkedin.com/in/satyanadella/details/experience/",
    "https://medium.com/@user/notes-4f2a",
    "https://www.dropbox.com/sh/abcd1234/AAdrop-share",
    "https://zoom.us/j/1234567890?pwd=abcdef",
    "https://www.notion.so/Team-wiki-8a2b1c4d5e6f",
    "https://trello.com/b/demo-board/welcome",
    "https://www.figma.com/file/abc123/Design-System",
    "https://community.cloudflare.com/t/help-me-with-dns-records/92510",
    "https://www.instagram.com/explore/tags/fishing/",
    "https://www.facebook.com/marketplace/112233445566/",
    "https://www.wellsfargo.com/checking/mortgage-calculator/",
    "https://www.chase.com/personal/credit-cards/chase-freedom",
    "https://www.ebay.com/itm/123456789012?hash=item4abc:rec",
    "https://mailchi.mp/rightinbox/frequently-made-promises",
    "https://www.amazon.de/s?k=tastatur&language=de_DE",
    "https://www.walmart.com/ip/576056503?athena_template=high_sym",
    "https://stackoverflow.com/tags/python/info",
    "https://www.python.org/psf/records/",
    "https://www.reddit.com/r/AskReddit/comments/abc123/what_is_the_best/?sort=top",
    "https://www.netflix.com/browse/genre/83",
]

sticky = [
    "http://10.0.0.1/bank/login",
    "http://192.0.2.10/login/paypal",
    "paypal.com.account-verify.example-secure.top/login",
    "secure-google-login.example.top/verify",
    "appleid.apple.com.account-check.example.org/signin",
    "microsoft-login-reset.example.net/account/verify",
    "amazon.security-alert.example.com/login",
    "coinbase-wallet-confirm.example.top/update",
    "http://203.0.113.55:8080/.well-known/id/bank.php",
    "http://198.51.100.77/paypal.example/index2.php",
    "dhl-tracking-redelivery.example-support.top/inbox",
    "steamcommunity.com.trade.example.cn/giftcards/scam",
    "https://192.0.2.33/wellsfargo.com/session/renew",
    "icloud-find-iphone.example-alerts.net/verify",
    "http://paypal-payments.mitsecuresystem.xyz/cgi/webapps",
    "update-your-account.example-signinpage.org/step2",
    "mail-inbox-verify.example-netsol.top/webmail/login",
    "http://198.51.100.9/bankofamerica.com/login/verify.php",
    "https://security-bank-drop.example-billing.top/payees",
    "coinbase-coinbase-coinbase.example-alarming-pump.online/claim",
    "https://apple-com-security.example-verify-user.net/support/id",
    "netflix-billing-update.strikinglydns.com/account",
    "zelle-transfer-hold.example-usbank-alerts.com/login",
    "http://203.0.113.88/login-service.de.mailbox-verifizieren.top",
    "fancy-exotic-reserved-brandmybrand-cdn.example-login-page.org/auth",
    "https://facebook-account-locked.example-disable-alert.top/proof",
    "https://login-libreon-xrp-wallet.webnode.page/wallet/moonpay",
    "https://yahoo-mail-verify.example-alert-reset.top/account/recover",
    "https://outlook-office365-verify.example-microsoftcloud.top/owa/auth",
    "https://dropbox-paper-sync.example-file-share.top/secure/upload",
]

assert len(bare) == 40 and len(pathed) == 40 and len(sticky) == 30

with open("tests/live_probe_urls.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["url", "label"])
    for u in bare:
        w.writerow([u, "legitimate"])
    for u in pathed:
        w.writerow([u, "legitimate"])
    for u in sticky:
        w.writerow([u, "phishing"])

print("legit:", len(bare) + len(pathed), "phishing:", len(sticky))
