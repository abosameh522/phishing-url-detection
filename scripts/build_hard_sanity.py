"""Build tests/hard_sanity_urls.csv: non-trivial legit URLs and non-obvious phishing strings.

Phishing strings come ONLY from local feed snapshots (data/raw/fresh, data/external);
they are never requested or resolved. Selection avoids URLs whose text already
contains the obvious credential keywords so the sanity check is not trivially passed.
"""
from pathlib import Path
import csv, re, random

random.seed(42)

SUSPICIOUS_WORDS = ("login", "signin", "sign-in", "verify", "secure", "account", "password",
                    "update", "confirm", "wallet", "credential", "billing", "unlock",
                    "recover", "authenticate", "webscr", "banking", "webservices")

phish = []
seen = set()

# Fresh feed snapshots, strings only
sources = [
    "data/raw/fresh/openphish_2026-11-05.txt",
    "data/external/phishing_database/active.txt",
]
for src in sources:
    p = Path(src)
    if not p.exists():
        continue
    lines = [l.strip() for l in p.open(encoding="utf-8", errors="replace") if l.strip()]
    random.shuffle(lines)
    for s in lines:
        low = s.lower()
        host_part = low.split("//", 1)[-1].split("/", 1)[0].split("?", 1)[0]
        # Non-trivial: keyword NOT in the whole URL text where possible; else keep only
        # keyword-free host/paths but exclude plain IP hosts (too easy)
        if any(w in low for w in SUSPICIOUS_WORDS):
            continue
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}", host_part):  # bare-IP hosts
            continue
        if len(s) > 120:  # keep readable examples
            continue
        if s in seen:
            continue
        seen.add(s)
        phish.append(s)
        if len(phish) >= 110:
            break
    if len(phish) >= 110:
        break

# Legit URLs with real paths/queries on popular sites and hosted platforms.
# Hand-curated real-world patterns (strings only, never fetched).
legit = [
    "https://github.com/psf/requests/issues?q=is%3Apr+sort%3Aupdated-desc",
    "https://github.com/kubernetes/kubernetes/pull/110254/files#diff-4ac32fa7c1f6",
    "https://stackoverflow.com/questions/231767/what-does-the-yield-keyword-do?answertab=votes",
    "https://www.amazon.com/s?k=mechanical+keyboard&ref=nb_sb_noss&rh=n%3A541966",
    "https://www.amazon.com/dp/B08N5WRWNW?ref_= Oct_Oct%.asin",
    "https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=RDdQw4w9WgXcQ&index=1",
    "https://en.wikipedia.org/wiki/Phishing?printable=yes#section-3",
    "https://www.google.com/search?q=coffee+near+me&tbm=lcl&hl=en",
    "https://docs.google.com/spreadsheets/d/1abc123/edit#gid=0",
    "https://docs.google.com/forms/d/e/1FAIpQLSd9Q0/viewform?usp=sf_link",
    "https://www.microsoft.com/en-us/microsoft-365/roadmap?filters=&searchterms=teams",
    "https://support.apple.com/en-us/HT204053",
    "https://apple.com/iphone-15-pro/specs/",
    "https://developer.mozilla.org/en-US/docs/Web/JavaScript?utm_source=mdn",
    "https://www.reddit.com/r/AskProgramming/comments/abc123/how_do_i/?sort=top",
    "https://x.com/elonmusk/status/1733164616392010100",
    "https://www.linkedin.com/in/satyanadella/details/experience/",
    "https://www.netflix.com/browse/genre/83?dv=1506",
    "https://mail.protection.outlook.com/EWS/Exchange.asmx",
    "https://about.meta.com/brand/resources/instagram/instagram/",
    "https://www.paypal.com/us/smarthelp/home",
    "https://www.wellsfargo.com/checking/",
    "https://www.chase.com/personal/credit-cards/chase-freedom",
    "https://outlook.office.com/mail/inbox/?department=eng",
    "https://teams.microsoft.com/v2/?tenantId=common",
    "https://gitlab.com/gitlab-org/gitlab/-/issues?scope=all&state=opened",
    "https://bitbucket.org/atlassian/python/pull-requests/",
    "https://codeberg.org/forgejo/forgejo/releases/tag/v7.0.0",
    "https://sourceforge.net/projects/sevenzip/files/7-Zip/23.01/",
    "https://pypi.org/project/requests/2.31.0/",
    "https://www.npmjs.com/package/express?activeTab=versions",
    "https://hub.docker.com/_/postgres/tags?page=1&ordering=last_updated",
    "https://www.kaggle.com/datasets/phreshphish/phreshphish/discussion",
    "https://news.ycombinator.com/item?id=38354361",
    "https://meta.stackexchange.com/questions/tagged/feature-request?page=3&tab=newest",
    "https://www.zillow.com/homes/for_rent/Cambridge,-MA_rb/?searchQueryState={}",
    "https://www.booking.com/hotel/us/marriott-marquis.html?checkin=2026-12-01&adults=2",
    "https://airbnb.com/rooms/12345678?check_in=2026-12-01&guests=2",
    "https://www.expedia.com/Hotel-Search?destination=Paris&adults=2",
    "https://www.walmart.com/ip/Details/12345678?athena_template=high_sym",
    "https://www.ebay.com/itm/123456789?hash=item4abc:rec",
    "https://www.etsy.com/listing/123456789/handmade-mug?referrer=shop",
    "https://play.google.com/store/apps/details?id=com.whatsapp&hl=en_US",
    "https://apps.apple.com/us/app/instagram/id389801252",
    "https://medium.com/@user_123/how-to-secure-your-accounts-123abc",
    "https://substack.com/home/post/p-138900123",
    "https://www.arcgis.com/home/item.html?id=abc123",
    "https://console.aws.amazon.com/console/home?region=us-east-1#",
    "https://portal.azure.com/#blade/Microsoft_Azure_Billing/Subscriptions",
    "https://console.cloud.google.com/welcome?project=demo-123",
    "https://dashboard.stripe.com/test/payments?status=failed",
    "https://app.slack.com/client/T0123/C0123/thread/C0123-17335",
    "https://notion.so/Team-wiki-8a2b1c-4d5e6f?utm_source=team",
    "https://trello.com/b/abc123/team-roadmap?filter=overdue",
    "https://figma.com/file/abc123/Design-System?node-id=4%3A2",
    "https://www.figma.com/community/plugin/123/Icon-Library",
    "https://www.canva.com/design/DAF123/edit?ui=mc",
    "https://www.instagram.com/explore/tags/fishing/?hl=en",
    "https://twitter.com/.swing=.mentions",
    "https://www.twitch.tv/settings/profile?utm_source=creator",
    "https://www.crunchbase.com/organization/openai/recent_investments",
    "https://www.spotify.com/account/subscription/?utm_source=spotify",
    "https://open.spotify.com/album/4aawyAB9vmqN3uQ7FjRGTy?si=abcdef",
    "https://soundcloud.com/discover/sets/charts-top:all",
    "https://www.dropbox.com/sh/abc123/AADef123?dl=0",
    "https://drive.google.com/file/d/1abc123/view?usp=sharing",
    "https://onedrive.live.com/?id=root&cid=123ABC",
    "https://www.box.com/personal/files/123",
    "https://icloud.com/photos/#0123456789abc",
    "https://zoom.us/j/1234567890?pwd=abcdef",
    "https://meet.google.com/abc-defg-hij?hs=122",
    "https://web.telegram.org/k/#-1234567890",
    "https://discord.com/channels/123/456/789",
    "https://www.tumblr.com/dashboard?offset=20",
    "https://www.pinterest.com/pin/1234567890/",
    "https://www.imdb.com/title/tt0993846/episodes?ref_=tt_eps_sm",
    "https://rottentomatoes.com/m/spider-man_no_way_home/reviews?type=top_critics",
    "https://www.glassdoor.com/Overview/Working-at-OpenAI-EI_IE123.11,18.htm",
    "https://www.indeed.com/jobs?q=python&l=remote&fromage=1",
    "https://www.coursera.org/learn/machine-learning/lecture/abc",
    "https://www.udemy.com/course/the-complete-guide/?couponCode=BLACKFRIDAY",
    "https://www.edx.org/course/introduction-to-artificial-intelligence",
    "https://www.duolingo.com/lesson/unit/1/level/2",
    "https://www.chess.com/game/live/123456789",
    "https://lichess.org/training/weekly?browser=1",
    "https://www.allrecipes.com/recipe/12345/no-knead-bread/",
    "https://www.foodnetwork.com/recipes/articles/50-dinner-ideas",
    "https://www.epicurious.com/recipes/food/views/pasta",
    "https://www.yummly.com/recipe/Spaghetti-Bolognese-123",
    "https://www.strava.com/activities/1234567890/analysis",
    "https://www.myfitnesspal.com/food/diary?date=2026-11-04",
    "https://www.audible.com/listening-guides/mystery-thriller",
    "https://www.goodreads.com/book/show/123456789.Project-Hail-Mary",
    "https://www.overdrive.com/media/1234567/audio-book",
    "https://www.billboard.com/charts/hot-100/?week=2026-11-04",
    "https://www.rottentomatoes.com/browse/tv_series_browse:genres~drama~",
    "https://www.metacritic.com/browse/game/release-date/new-releases/date",
    "https://store.steampowered.com/app/1091500/Cyberpunk_2077/",
    "https://store.steampowered.com/sale/fall-sale?category=Action",
    "https://www.epicgames.com/store/en-US/p/fortnite",
    "https://battlelog.battlefield.com/bf4/servers/show/pc/123-abc/",
    "https://www.minecraft.net/en-us/download/server/bedrock/",
    "https://www.rocketleague.com/com rank/rank-2v2-doubles-pc-ps4",
    "https://www.chess.com/daily/news/how-to-play-ruy-lopez",
    "https://scholar.google.com/citations?user=abc123&hl=en",
    "https://www.researchgate.net/publication/123456_Deep_Learning",
    "https://arxiv.org/abs/2010.11929v2",
    "https://www.nature.com/articles/s41586-023-06600-8",
    "https://ieeexplore.ieee.org/document/9156600?denied=",
    "https://dl.acm.org/doi/10.1145/3442188.3445922",
    "https://www.biorxiv.org/content/10.1101/2023.06.01.123456v1.full",
    "https://www.ncbi.nlm.nih.gov/pmc/articles/PMC1234567/",
    "https://www.nih.gov/news-events/news-releases/123",
    "https://www.who.int/news-room/fact-sheets/detail/measles",
    "https://www.cdc.gov/niosh/topics/noise/nnlstraining.html",
    "https://www.usa.gov/federal-agencies/list-of-agencies",
    "https://www.gov.uk/report-suspicious-emails-and-websites",
    "https://www.europol.europa.eu/crime-areas/cybercrime",
    "https://www.interpol.int/en/Crimes/Cybercrime",
    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    "https://first.org/cvss/v3.1/specification-document",
    "https://owasp.org/www-project-top-ten/2021/A03_2021-Injection",
    "https://www.mit.edu/people/specious/archives/2013/06/",
    "https://cs.stanford.edu/people/karpathy/talks/",
    "https://www.github.io.io/hard.example/one",
    "https://unstats.un.org/unsd/methodology/m49/overview/",
    "https://banking.tranco-list.eu/top-1m-csv/download",
    "https://transparencyreport.google.com/safe-browsing/overview?region=US",
    "https://weather.com/weather/today/l/123abc456def",
    "https://www.accuweather.com/en/us/new-york/10011/weather-forecast/349727",
    "https://www.timeanddate.com/worldclock/convert.html?iso=20261105T15",
    "https://dictionary.cambridge.org/dictionary/english/serendipity",
    "https://www.merriam-webster.com/dictionary/serendipity?utm_campaign=trending",
    "https://www.vocabulary.com/dictionary/petrichor/",
    "https://wolframalpha.com/input/?i=integrate+x%5E2+dx",
    "https://www.desmos.com/calculator/abc123def456",
    "https://regex101.com/r/abc123/1?testString=demo",
    "https://www.speedtest.net/result/16200012345",
    "https://pinboard.in/u:dan/t:machine-learning/",
    "https://www.courts.ca.gov/rules.htm?title=two",
    "https://www.sec.gov/edgar/browse/CIK=0000320193",
    "https://www.irs.gov/individuals/get-transcript",
    "https://ssllabs.com/ssltest/analyze.html?d=github.com",
    "https://haveibeenpwned.com/PwnedWebsites?filter=leak",
    "https://shields.io/badge/test-passing-brightgreen",
    "https://www.trustedshops.com/shop/certificate?shop=abc123",
    "https://developers.facebook.com/docs/messenger-platform/send-messages?locale=en_US",
    "https://developer.twitter.com/en/portal/dashboard",
    "https://console.firebase.google.com/u/0/project/abc123/overview",
    "https://app.codacy.com/gh/org/repo/pull-requests?branch=main",
    "https://www.railwaymuseum.org.uk/objects-and-stories/123",
    "https://artsandculture.google.com/asset/van-gogh-abc123",
    "https://www.si.edu/object/painting?collection=american",
    "https://archive.org/details/goodyear_202310",
    "https://archive.org/wayback/available?url=example.com",
    "https://www.gutenberg.org/ebooks/84?msg=thanks",
    "https://www.loc.gov/item/00694222/?fo=json",
    "https://britishmuseum.withgoogle.com/object/123",
    "https://myaccount.google.com/activitycontrols?ref=pr",
    "https://ads.google.com/aw/campaigns?utm_referrer=dashboard",
    "https://analytics.google.com/analytics/web/#/p/123456/reports",
    "https://business.google.com/reviews?hl=en&gl=US",
    "https://www.wayfair.com/furniture/sb0/abc123.html?search=desk",
    "https://www.homedepot.com/p/Details/123?selectedStore=1234",
    "https://www.lowes.com/pd/Item/1000123?cm_mmc=shop",
    "https://www.autotrader.com/cars-for-sale/vehicledetails.xhtml?listingId=123",
    "https://www.cars.com/vehicledetail/detail123/?/source=share",
    "https://www.fedex.com/apps/fedextrack/?action=track&trackingnumber=1234",
    "https://www.ups.com/track?tracknum=1Z999AA10123456784",
    "https://www.usps.com/shipping/trackandconfirm.htm?label=123",
    "https://www.paypal.com/myaccount/transfer/homepage/pay",
    "https://www.venmo.com/transaction/1234567890abcdef",
    "https://cash.app/$user/12345678901234567890",
    "https://www.revolut.com/payments/12345678-90ab/",
    "https://wise.com/plans/transfer/12345678/#/details",
    "https://www.gofundme.com/f/support-the-pets?utm_source=clipboard",
    "https://www.kickstarter.com/projects/creator/project/pledge",
    "https://www.indiegogo.com/projects/tech-gadget-refurbishing#/story",
    "https://www.patreon.com/posts/artist-update-12345",
    "https://www.producthunt.com/posts/new-tool?utm_source=ph",
    "https://www.indiehackers.com/post/launch-2023-11-abc",
    "https://stackoverflow.blog/2023/11/05/developer-mentality/",
    "https://dev.to/user/what-i-learned-this-week-4f2a",
    "https://css-tricks.com/snippets/css/complete-guide-grid/?utm=rss",
    "https://css-tricks.com/guides/grid/#section-iii",
    "https://web.dev/articles/fcp?hl=en",
    "https://www.smashingmagazine.com/2023/10/css-container-queries-guide/",
    "https://caniuse.com/?search=container-queries",
    "https://www.caniuse.com/table/?t=flexbox",
    "https://browserl.ist/?q=%3E%3D%201%25",
    "https://vitejs.dev/guide/ssr.html#server-side-rendering",
    "https://webpack.js.org/configuration/entry-context/?utm=docs",
]


with open("tests/hard_sanity_urls.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["url", "label"])
    for s in legit:
        w.writerow([s, "legitimate"])
    for s in phish:
        w.writerow([s, "phishing"])

print("legit rows:", len(legit), "phish rows:", len(phish))
print("total:", len(legit) + len(phish))
