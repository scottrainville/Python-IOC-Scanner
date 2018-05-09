import datetime
import re
import os


#Takes in raw .txt export of an email and extracts IOCs, runs them over a whitelist and outputs to .csv.
#CSV format: date, description, type (domain/IP), ioc

#########################
####      PARAMS     ####
#########################

inputFileName = "message.txt"   #This is the file the Outlook VB script creates
outputFileName = "IOCs.csv" #This is the CSV file to output to.
whitelistFileName = "whitelist.txt"    #Whitelist to run scanned IOCs against. Large files will slow things down.

date = datetime.datetime.now().strftime("%m/%d/%Y")

ipAddresses = []
definiteDomainNames = []
maybeDomainNames = []
domainNamesWhitelist = []

#List of file extensions: Any domain IOCs ending in this will be discarded that aren't a TLD. removed some that are also possible TLDs.
fileExtensions = [ ".wav", ".wma", ".7z", ".deb", ".pkg", ".rpm", ".bin", ".dmg", ".iso", ".csv", ".dat", ".db", ".log", ".sql", ".tar", ".xml", ".bat", ".exe", ".jar", ".msi", ".ps1", ".bmp", ".gif", ".ico", ".jpeg", ".jpg", ".png", ".psd", ".tif", ".tiff", ".html", ".htm", ".js", ".php", ".jsp", ".xls", ".xlsx", ".xlr", ".cfg", ".dll", ".ini", ".lnk", ".sys", ".tmp", ".avi", ".flv", ".mp4", ".wmv", ".doc", ".docx", ".pdf", ".rtf", ".txt" ]

#List of TLDs. Removed some that are also possible file extensions.
TLDs = [ ".aaa", ".aarp", ".abarth", ".abb", ".abbott", ".abbvie", ".abc", ".able", ".abogado", ".abudhabi", ".ac", ".academy", ".accenture", ".accountant", ".accountants", ".aco", ".active", ".actor", ".ad", ".adac", ".ads", ".adult", ".ae", ".aeg", ".aero", ".aetna", ".af", ".afamilycompany", ".afl", ".africa", ".ag", ".agakhan", ".agency", ".ai", ".aig", ".aigo", ".airbus", ".airforce", ".airtel", ".akdn", ".al", ".alfaromeo", ".alibaba", ".alipay", ".allfinanz", ".allstate", ".ally", ".alsace", ".alstom", ".am", ".americanexpress", ".americanfamily", ".amex", ".amfam", ".amica", ".amsterdam", ".analytics", ".android", ".anquan", ".anz", ".ao", ".aol", ".apartments", ".app", ".apple", ".aq", ".aquarelle", ".ar", ".arab", ".aramco", ".archi", ".army", ".arpa", ".art", ".arte", ".as", ".asda", ".asia", ".associates", ".at", ".athleta", ".attorney", ".au", ".auction", ".audi", ".audible", ".audio", ".auspost", ".author", ".auto", ".autos", ".avianca", ".aw", ".aws", ".ax", ".axa", ".az", ".azure", ".ba", ".baby", ".baidu", ".banamex", ".bananarepublic", ".band", ".bank", ".bar", ".barcelona", ".barclaycard", ".barclays", ".barefoot", ".bargains", ".baseball", ".basketball", ".bauhaus", ".bayern", ".bb", ".bbc", ".bbt", ".bbva", ".bcg", ".bcn", ".bd", ".be", ".beats", ".beauty", ".beer", ".bentley", ".berlin", ".best", ".bestbuy", ".bet", ".bf", ".bg", ".bh", ".bharti", ".bi", ".bible", ".bid", ".bike", ".bing", ".bingo", ".bio", ".biz", ".bj", ".black", ".blackfriday", ".blanco", ".blockbuster", ".blog", ".bloomberg", ".blue", ".bm", ".bms", ".bmw", ".bn", ".bnl", ".bnpparibas", ".bo", ".boats", ".boehringer", ".bofa", ".bom", ".bond", ".boo", ".book", ".booking", ".bosch", ".bostik", ".boston", ".bot", ".boutique", ".box", ".br", ".bradesco", ".bridgestone", ".broadway", ".broker", ".brother", ".brussels", ".bs", ".bt", ".budapest", ".bugatti", ".build", ".builders", ".business", ".buy", ".buzz", ".bv", ".bw", ".by", ".bz", ".bzh", ".ca", ".cafe", ".cal", ".call", ".calvinklein", ".cam", ".camera", ".camp", ".cancerresearch", ".canon", ".capetown", ".capital", ".capitalone", ".car", ".caravan", ".cards", ".care", ".career", ".careers", ".cars", ".cartier", ".casa", ".case", ".caseih", ".cash", ".casino", ".cat", ".catering", ".catholic", ".cba", ".cbn", ".cbre", ".cbs", ".cc", ".cd", ".ceb", ".center", ".ceo", ".cern", ".cf", ".cfa", ".cfd", ".cg", ".ch", ".chanel", ".channel", ".chase", ".chat", ".cheap", ".chintai", ".christmas", ".chrome", ".chrysler", ".church", ".ci", ".cipriani", ".circle", ".cisco", ".citadel", ".citi", ".citic", ".city", ".cityeats", ".ck", ".cl", ".claims", ".cleaning", ".click", ".clinic", ".clinique", ".clothing", ".cloud", ".club", ".clubmed", ".cm", ".cn", ".co", ".coach", ".codes", ".coffee", ".college", ".cologne", ".com", ".comcast", ".commbank", ".community", ".company", ".compare", ".computer", ".comsec", ".condos", ".construction", ".consulting", ".contact", ".contractors", ".cooking", ".cookingchannel", ".cool", ".coop", ".corsica", ".country", ".coupon", ".coupons", ".courses", ".cr", ".credit", ".creditcard", ".creditunion", ".cricket", ".crown", ".crs", ".cruise", ".cruises", ".csc", ".cu", ".cuisinella", ".cv", ".cw", ".cx", ".cy", ".cymru", ".cyou", ".cz", ".dabur", ".dad", ".dance", ".data", ".date", ".dating", ".datsun", ".day", ".dclk", ".dds", ".de", ".deal", ".dealer", ".deals", ".degree", ".delivery", ".dell", ".deloitte", ".delta", ".democrat", ".dental", ".dentist", ".desi", ".design", ".dev", ".dhl", ".diamonds", ".diet", ".digital", ".direct", ".directory", ".discount", ".discover", ".dish", ".diy", ".dj", ".dk", ".dm", ".dnp", ".do", ".docs", ".doctor", ".dodge", ".dog", ".doha", ".domains", ".dot", ".download", ".drive", ".dtv", ".dubai", ".duck", ".dunlop", ".duns", ".dupont", ".durban", ".dvag", ".dvr", ".dz", ".earth", ".eat", ".ec", ".eco", ".edeka", ".edu", ".education", ".ee", ".eg", ".email", ".emerck", ".energy", ".engineer", ".engineering", ".enterprises", ".epost", ".epson", ".equipment", ".er", ".ericsson", ".erni", ".es", ".esq", ".estate", ".esurance", ".et", ".etisalat", ".eu", ".eurovision", ".eus", ".events", ".everbank", ".exchange", ".expert", ".exposed", ".express", ".extraspace", ".fage", ".fail", ".fairwinds", ".faith", ".family", ".fan", ".fans", ".farm", ".farmers", ".fashion", ".fast", ".fedex", ".feedback", ".ferrari", ".ferrero", ".fi", ".fiat", ".fidelity", ".fido", ".film", ".final", ".finance", ".financial", ".fire", ".firestone", ".firmdale", ".fish", ".fishing", ".fit", ".fitness", ".fj", ".fk", ".flickr", ".flights", ".flir", ".florist", ".flowers", ".fly", ".fm", ".fo", ".foo", ".food", ".foodnetwork", ".football", ".ford", ".forex", ".forsale", ".forum", ".foundation", ".fox", ".fr", ".free", ".fresenius", ".frl", ".frogans", ".frontdoor", ".frontier", ".ftr", ".fujitsu", ".fujixerox", ".fun", ".fund", ".furniture", ".futbol", ".fyi", ".ga", ".gal", ".gallery", ".gallo", ".gallup", ".game", ".games", ".gap", ".garden", ".gb", ".gbiz", ".gd", ".gdn", ".ge", ".gea", ".gent", ".genting", ".george", ".gf", ".gg", ".ggee", ".gh", ".gi", ".gift", ".gifts", ".gives", ".giving", ".gl", ".glade", ".glass", ".gle", ".global", ".globo", ".gm", ".gmail", ".gmbh", ".gmo", ".gmx", ".gn", ".godaddy", ".gold", ".goldpoint", ".golf", ".goo", ".goodhands", ".goodyear", ".goog", ".google", ".gop", ".got", ".gov", ".gp", ".gq", ".gr", ".grainger", ".graphics", ".gratis", ".green", ".gripe", ".grocery", ".group", ".gs", ".gt", ".gu", ".guardian", ".gucci", ".guge", ".guide", ".guitars", ".guru", ".gw", ".gy", ".hair", ".hamburg", ".hangout", ".haus", ".hbo", ".hdfc", ".hdfcbank", ".health", ".healthcare", ".help", ".helsinki", ".here", ".hermes", ".hgtv", ".hiphop", ".hisamitsu", ".hitachi", ".hiv", ".hk", ".hkt", ".hm", ".hn", ".hockey", ".holdings", ".holiday", ".homedepot", ".homegoods", ".homes", ".homesense", ".honda", ".honeywell", ".horse", ".hospital", ".host", ".hosting", ".hot", ".hoteles", ".hotels", ".hotmail", ".house", ".how", ".hr", ".hsbc", ".ht", ".hu", ".hughes", ".hyatt", ".hyundai", ".ibm", ".icbc", ".ice", ".icu", ".id", ".ie", ".ieee", ".ifm", ".ikano", ".il", ".im", ".imamat", ".imdb", ".immo", ".immobilien", ".in", ".industries", ".infiniti", ".info", ".ing", ".ink", ".institute", ".insurance", ".insure", ".int", ".intel", ".international", ".intuit", ".investments", ".io", ".ipiranga", ".iq", ".ir", ".irish", ".is", ".iselect", ".ismaili", ".ist", ".istanbul", ".it", ".itau", ".itv", ".iveco", ".iwc", ".jaguar", ".java", ".jcb", ".jcp", ".je", ".jeep", ".jetzt", ".jewelry", ".jio", ".jlc", ".jll", ".jm", ".jmp", ".jnj", ".jo", ".jobs", ".joburg", ".jot", ".joy", ".jp", ".jpmorgan", ".jprs", ".juegos", ".juniper", ".kaufen", ".kddi", ".ke", ".kerryhotels", ".kerrylogistics", ".kerryproperties", ".kfh", ".kg", ".kh", ".ki", ".kia", ".kim", ".kinder", ".kindle", ".kitchen", ".kiwi", ".km", ".kn", ".koeln", ".komatsu", ".kosher", ".kp", ".kpmg", ".kpn", ".kr", ".krd", ".kred", ".kuokgroup", ".kw", ".ky", ".kyoto", ".kz", ".la", ".lacaixa", ".ladbrokes", ".lamborghini", ".lamer", ".lancaster", ".lancia", ".lancome", ".land", ".landrover", ".lanxess", ".lasalle", ".lat", ".latino", ".latrobe", ".law", ".lawyer", ".lb", ".lc", ".lds", ".lease", ".leclerc", ".lefrak", ".legal", ".lego", ".lexus", ".lgbt", ".li", ".liaison", ".lidl", ".life", ".lifeinsurance", ".lifestyle", ".lighting", ".like", ".lilly", ".limited", ".limo", ".lincoln", ".linde", ".link", ".lipsy", ".live", ".living", ".lixil", ".lk", ".llc", ".loan", ".loans", ".locker", ".locus", ".loft", ".lol", ".london", ".lotte", ".lotto", ".love", ".lpl", ".lplfinancial", ".lr", ".ls", ".lt", ".ltd", ".ltda", ".lu", ".lundbeck", ".lupin", ".luxe", ".luxury", ".lv", ".ly", ".ma", ".macys", ".madrid", ".maif", ".maison", ".makeup", ".man", ".management", ".mango", ".map", ".market", ".marketing", ".markets", ".marriott", ".marshalls", ".maserati", ".mattel", ".mba", ".mc", ".mckinsey", ".md", ".me", ".med", ".media", ".meet", ".melbourne", ".meme", ".memorial", ".men", ".menu", ".meo", ".merckmsd", ".metlife", ".mg", ".mh", ".miami", ".microsoft", ".mil", ".mini", ".mint", ".mit", ".mitsubishi", ".mk", ".ml", ".mlb", ".mls", ".mm", ".mma", ".mn", ".mo", ".mobi", ".mobile", ".mobily", ".moda", ".moe", ".moi", ".mom", ".monash", ".money", ".monster", ".mopar", ".mormon", ".mortgage", ".moscow", ".moto", ".motorcycles", ".movie", ".movistar", ".mp", ".mq", ".mr", ".ms", ".msd", ".mt", ".mtn", ".mtr", ".mu", ".museum", ".mutual", ".mv", ".mw", ".mx", ".my", ".mz", ".na", ".nab", ".nadex", ".nagoya", ".name", ".nationwide", ".natura", ".navy", ".nba", ".nc", ".ne", ".nec", ".net", ".netbank", ".netflix", ".network", ".neustar", ".new", ".newholland", ".news", ".next", ".nextdirect", ".nexus", ".nf", ".nfl", ".ng", ".ngo", ".nhk", ".ni", ".nico", ".nike", ".nikon", ".ninja", ".nissan", ".nissay", ".nl", ".no", ".nokia", ".northwesternmutual", ".norton", ".now", ".nowruz", ".nowtv", ".np", ".nr", ".nra", ".nrw", ".ntt", ".nu", ".nyc", ".nz", ".obi", ".observer", ".off", ".office", ".okinawa", ".olayan", ".olayangroup", ".oldnavy", ".ollo", ".om", ".omega", ".one", ".ong", ".onl", ".online", ".onyourside", ".ooo", ".open", ".oracle", ".orange", ".org", ".organic", ".origins", ".osaka", ".otsuka", ".ott", ".ovh", ".pa", ".page", ".panasonic", ".panerai", ".paris", ".pars", ".partners", ".parts", ".party", ".passagens", ".pay", ".pccw", ".pe", ".pet", ".pf", ".pfizer", ".pg", ".ph", ".pharmacy", ".phd", ".philips", ".phone", ".photo", ".photography", ".photos", ".physio", ".piaget", ".pics", ".pictet", ".pictures", ".pid", ".pin", ".ping", ".pink", ".pioneer", ".pizza", ".pk", ".pl", ".place", ".play", ".playstation", ".plumbing", ".plus", ".pm", ".pn", ".pnc", ".pohl", ".poker", ".politie", ".porn", ".post", ".pr", ".pramerica", ".praxi", ".press", ".prime", ".pro", ".prod", ".productions", ".prof", ".progressive", ".promo", ".properties", ".property", ".protection", ".pru", ".prudential", ".ps", ".pt", ".pub", ".pw", ".pwc", ".qa", ".qpon", ".quebec", ".quest", ".qvc", ".racing", ".radio", ".raid", ".re", ".read", ".realestate", ".realtor", ".realty", ".recipes", ".red", ".redstone", ".redumbrella", ".rehab", ".reise", ".reisen", ".reit", ".reliance", ".ren", ".rent", ".rentals", ".repair", ".report", ".republican", ".rest", ".restaurant", ".review", ".reviews", ".rexroth", ".rich", ".richardli", ".ricoh", ".rightathome", ".ril", ".rio", ".rip", ".rmit", ".ro", ".rocher", ".rocks", ".rodeo", ".rogers", ".room", ".rs", ".rsvp", ".ru", ".rugby", ".ruhr", ".run", ".rw", ".rwe", ".ryukyu", ".sa", ".saarland", ".safe", ".safety", ".sakura", ".sale", ".salon", ".samsclub", ".samsung", ".sandvik", ".sandvikcoromant", ".sanofi", ".sap", ".sapo", ".sarl", ".sas", ".save", ".saxo", ".sb", ".sbi", ".sbs", ".sc", ".sca", ".scb", ".schaeffler", ".schmidt", ".scholarships", ".school", ".schule", ".schwarz", ".science", ".scjohnson", ".scor", ".scot", ".sd", ".se", ".search", ".seat", ".secure", ".security", ".seek", ".select", ".sener", ".services", ".ses", ".seven", ".sew", ".sex", ".sexy", ".sfr", ".sg", ".sh", ".shangrila", ".sharp", ".shaw", ".shell", ".shia", ".shiksha", ".shoes", ".shop", ".shopping", ".shouji", ".show", ".showtime", ".shriram", ".si", ".silk", ".sina", ".singles", ".site", ".sj", ".sk", ".ski", ".skin", ".sky", ".skype", ".sl", ".sling", ".sm", ".smart", ".smile", ".sn", ".sncf", ".so", ".soccer", ".social", ".softbank", ".software", ".sohu", ".solar", ".solutions", ".song", ".sony", ".soy", ".space", ".spiegel", ".sport", ".spot", ".spreadbetting", ".sr", ".srl", ".srt", ".st", ".stada", ".staples", ".star", ".starhub", ".statebank", ".statefarm", ".statoil", ".stc", ".stcgroup", ".stockholm", ".storage", ".store", ".stream", ".studio", ".study", ".style", ".su", ".sucks", ".supplies", ".supply", ".support", ".surf", ".surgery", ".suzuki", ".sv", ".swatch", ".swiftcover", ".swiss", ".sx", ".sy", ".sydney", ".symantec", ".systems", ".sz", ".tab", ".taipei", ".talk", ".taobao", ".target", ".tatamotors", ".tatar", ".tattoo", ".tax", ".taxi", ".tc", ".tci", ".td", ".tdk", ".team", ".tech", ".technology", ".tel", ".telecity", ".telefonica", ".temasek", ".tennis", ".teva", ".tf", ".tg", ".th", ".thd", ".theater", ".theatre", ".tiaa", ".tickets", ".tienda", ".tiffany", ".tips", ".tires", ".tirol", ".tj", ".tjmaxx", ".tjx", ".tk", ".tkmaxx", ".tl", ".tm", ".tmall", ".tn", ".to", ".today", ".tokyo", ".tools", ".top", ".toray", ".toshiba", ".total", ".tours", ".town", ".toyota", ".toys", ".tr", ".trade", ".trading", ".training", ".travel", ".travelchannel", ".travelers", ".travelersinsurance", ".trust", ".trv", ".tt", ".tube", ".tui", ".tunes", ".tushu", ".tv", ".tvs", ".tw", ".tz", ".ua", ".ubank", ".ubs", ".uconnect", ".ug", ".uk", ".unicom", ".university", ".uno", ".uol", ".ups", ".us", ".uy", ".uz", ".va", ".vacations", ".vana", ".vanguard", ".vc", ".ve", ".vegas", ".ventures", ".verisign", ".versicherung", ".vet", ".vg", ".vi", ".viajes", ".video", ".vig", ".viking", ".villas", ".vin", ".vip", ".virgin", ".visa", ".vision", ".vista", ".vistaprint", ".viva", ".vivo", ".vlaanderen", ".vn", ".vodka", ".volkswagen", ".volvo", ".vote", ".voting", ".voto", ".voyage", ".vu", ".vuelos", ".wales", ".walmart", ".walter", ".wang", ".wanggou", ".warman", ".watch", ".watches", ".weather", ".weatherchannel", ".webcam", ".weber", ".website", ".wed", ".wedding", ".weibo", ".weir", ".wf", ".whoswho", ".wien", ".wiki", ".williamhill", ".win", ".windows", ".wine", ".winners", ".wme", ".wolterskluwer", ".woodside", ".work", ".works", ".world", ".wow", ".ws", ".wtc", ".wtf", ".xbox", ".xerox", ".xfinity", ".xihuan", ".xin", ".xn--11b4c3d", ".xn--1ck2e1b", ".xn--1qqw23a", ".xn--2scrj9c", ".xn--30rr7y", ".xn--3bst00m", ".xn--3ds443g", ".xn--3e0b707e", ".xn--3hcrj9c", ".xn--3oq18vl8pn36a", ".xn--3pxu8k", ".xn--42c2d9a", ".xn--45br5cyl", ".xn--45brj9c", ".xn--45q11c", ".xn--4gbrim", ".xn--54b7fta0cc", ".xn--55qw42g", ".xn--55qx5d", ".xn--5su34j936bgsg", ".xn--5tzm5g", ".xn--6frz82g", ".xn--6qq986b3xl", ".xn--80adxhks", ".xn--80ao21a", ".xn--80aqecdr1a", ".xn--80asehdb", ".xn--80aswg", ".xn--8y0a063a", ".xn--90a3ac", ".xn--90ae", ".xn--90ais", ".xn--9dbq2a", ".xn--9et52u", ".xn--9krt00a", ".xn--b4w605ferd", ".xn--bck1b9a5dre4c", ".xn--c1avg", ".xn--c2br7g", ".xn--cck2b3b", ".xn--cg4bki", ".xn--clchc0ea0b2g2a9gcd", ".xn--czr694b", ".xn--czrs0t", ".xn--czru2d", ".xn--d1acj3b", ".xn--d1alf", ".xn--e1a4c", ".xn--eckvdtc9d", ".xn--efvy88h", ".xn--estv75g", ".xn--fct429k", ".xn--fhbei", ".xn--fiq228c5hs", ".xn--fiq64b", ".xn--fiqs8s", ".xn--fiqz9s", ".xn--fjq720a", ".xn--flw351e", ".xn--fpcrj9c3d", ".xn--fzc2c9e2c", ".xn--fzys8d69uvgm", ".xn--g2xx48c", ".xn--gckr3f0f", ".xn--gecrj9c", ".xn--gk3at1e", ".xn--h2breg3eve", ".xn--h2brj9c", ".xn--h2brj9c8c", ".xn--hxt814e", ".xn--i1b6b1a6a2e", ".xn--imr513n", ".xn--io0a7i", ".xn--j1aef", ".xn--j1amh", ".xn--j6w193g", ".xn--jlq61u9w7b", ".xn--jvr189m", ".xn--kcrx77d1x4a", ".xn--kprw13d", ".xn--kpry57d", ".xn--kpu716f", ".xn--kput3i", ".xn--l1acc", ".xn--lgbbat1ad8j", ".xn--mgb9awbf", ".xn--mgba3a3ejt", ".xn--mgba3a4f16a", ".xn--mgba7c0bbn0a", ".xn--mgbaakc7dvf", ".xn--mgbaam7a8h", ".xn--mgbab2bd", ".xn--mgbai9azgqp6j", ".xn--mgbayh7gpa", ".xn--mgbb9fbpob", ".xn--mgbbh1a", ".xn--mgbbh1a71e", ".xn--mgbc0a9azcg", ".xn--mgbca7dzdo", ".xn--mgberp4a5d4ar", ".xn--mgbgu82a", ".xn--mgbi4ecexp", ".xn--mgbpl2fh", ".xn--mgbt3dhd", ".xn--mgbtx2b", ".xn--mgbx4cd0ab", ".xn--mix891f", ".xn--mk1bu44c", ".xn--mxtq1m", ".xn--ngbc5azd", ".xn--ngbe9e0a", ".xn--ngbrx", ".xn--node", ".xn--nqv7f", ".xn--nqv7fs00ema", ".xn--nyqy26a", ".xn--o3cw4h", ".xn--ogbpf8fl", ".xn--otu796d", ".xn--p1acf", ".xn--p1ai", ".xn--pbt977c", ".xn--pgbs0dh", ".xn--pssy2u", ".xn--q9jyb4c", ".xn--qcka1pmc", ".xn--qxam", ".xn--rhqv96g", ".xn--rovu88b", ".xn--rvc1e0am3e", ".xn--s9brj9c", ".xn--ses554g", ".xn--t60b56a", ".xn--tckwe", ".xn--tiq49xqyj", ".xn--unup4y", ".xn--vermgensberater-ctb", ".xn--vermgensberatung-pwb", ".xn--vhquv", ".xn--vuq861b", ".xn--w4r85el8fhu5dnra", ".xn--w4rs40l", ".xn--wgbh1c", ".xn--wgbl6a", ".xn--xhq521b", ".xn--xkc2al3hye2a", ".xn--xkc2dl3a5ee0h", ".xn--y9a3aq", ".xn--yfro4i67o", ".xn--ygbi2ammx", ".xn--zfr164b", ".xperia", ".xxx", ".xyz", ".yachts", ".yahoo", ".yamaxun", ".yandex", ".ye", ".yodobashi", ".yoga", ".yokohama", ".you", ".youtube", ".yt", ".yun", ".za", ".zappos", ".zara", ".zero", ".zippo", ".zm", ".zone", ".zuerich", ".zw" ]


#########################
####    FUNCTIONS    ####
#########################

#Sees if a line is supposed to be ignored, such as "Sender: xyz".
def toIgnore(string):
    if ((string.find("from:") != -1) or (string.find("sent:") != -1) or (string.find("to:") != -1) or (string.find("cc:") != -1) or (string.find("subject:") != -1) or (string.find("attachment:") != -1) or (string.find("sender:") != -1) or (string.find("attachments:") != -1)):
        return True
    else:
        return False

#Sees if a domain is in the whitelist file. Deprecated, replaced with v2.
def isWhiteListed(ioc):
    for line in whitelist:
        if (ioc == line.rstrip("\n")):
            return True
        
    #If not found and if "www." present, re-run the search with the "www." stripped out.
    if "www." in ioc:
         for line in whitelist:
             if (ioc.replace("www.",'') == line.rstrip("\n")):
                return True
    return False

#Sees if a domain is in the whitelist file. Will count subdomains of whitelisted domains as whitelisted too.
def isWhiteListed2(ioc):
    for line in whitelist:
        line = line.rstrip("\n")
        location = ioc.find(line)  #If the whitelist item is contained in the IOC
        if ((location == 0) and (line == ioc)): #If the IOC and the whitelist item are exactly the same
            return True
        if (location > 0):
            #Check that the character preceding the location of the whitelist string in the IOC is "."
            if (ioc[location - 1] == '.'):
                #Check that the whitelist string is at the end of the IOC
                if (location == (len(ioc) - len(line))):
                    return True
    return False

#Determines if an IOC has an official TLD.
def officialTLD(ioc):
    for tld in TLDs:
        location = ioc.find(tld)    #Make sure the file tld is at the END of the ioc
        if ((location >= 0) and (location == (len(ioc) - len(tld)))):
            return True
    return False

#Determines if an IOC is actually a filename, like "file.jpg"
def isFileName(ioc):
    for extension in fileExtensions:
        location = ioc.find(extension)
        if ((location >= 0) and (location == (len(ioc) - len(extension)))):    #Make sure the file extension is at the END of the ioc
            return True
    return False

#Determines if an ioc contained in a string is part of an email address
def isEmailAddr(line, ioc):
    if line.find(ioc) > 0:  #If there's at least one character before the IOC in the string:
        if(line[line.find(ioc) -1] == "@"):
            return True #Return if the preceding character is "@"
        
    if ((line.find(ioc) + len(ioc)) < len(line)): #If there's at least one character after the end of the IOC in the string:     
        if (line[line.find(ioc) + len(ioc)] == "@"):
            return True    #Return if the character after the IOC is "@"
        
    return False
    
#########################
####      MAIN       ####
#########################

#Load in the whitelist as a variable
try:
    wlfd = open(whitelistFileName, "r")
except:
    print("Whitelist file not found!")
    input("Press enter to continue.")
    quit()

whitelist = wlfd.readlines()
wlfd.close()

desc = input("Enter the Description: ") #
desc=desc.replace(",", "")      #Strip commas, that would ruin the csv :(

#Loop for reading each line of the file. Put all regex scanning and appending to IOC arrays here.
with open(inputFileName) as fd:
    for line in fd:
        line = line.rstrip("\n").replace('[', '').replace(']', '').lower()    #Get rid of line breaks and brackets, convert all to lowercase
        if (toIgnore(line) == False):
            tempIpArray = []
            tempDomainArray = []

            #Pull out IOCs with regex
            tempIpArray.append(re.findall('(?<![0-9])(?:(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)\.){3}(?:1\d\d|2[0-5][0-5]|2[0-4]\d|0?[1-9]\d|0?0?\d)', line))
            tempDomainArray.append(re.findall(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,20}', line))

            for ips in tempIpArray:
                for ip in ips:
                    #if (isWhiteListed(ip) == False):
                    if ip not in ipAddresses:       #Only add if it's not already in the array, ignoring dupes
                        ipAddresses.append(ip)
                        
            for domains in tempDomainArray:
                for domain in domains:
                    if isFileName(domain) == False:
                        if ((domain not in definiteDomainNames) and (domain not in domainNamesWhitelist) and (domain not in maybeDomainNames)):   #Only add if it's not already in the array, ignoring dupes
                            if (isEmailAddr(line, domain) == False):    #If the IOC appears to be part of an email address, ignore.
                                if isWhiteListed2(domain):   #if it's whitelisted, add to whitelisted array. If not, add to normal arrays.
                                    domainNamesWhitelist.append(domain)
                                elif (officialTLD(domain)):
                                    definiteDomainNames.append(domain)
                                elif (isFileName(domain) == False):
                                    maybeDomainNames.append(domain)
                                      

#Output to the .csv file
success = 0
while (success == 0):
    try:
        ofh = open(outputFileName, "a") #Open output .csv file
        success = 1
    except:
        print("Error opening csv file for writing! Is someone using it?")
        wait = input("PRESS ENTER TO TRY AGAIN.")

if (len(ipAddresses) > 0):
    print("\n\n****IP ADDRESSES****")

#Write IPs to csv file
for ip in ipAddresses:
    print(ip)
    ofh.write(date + ',' + desc + ',' + "IP" + ',' + ip + '\n')

if (len(definiteDomainNames) > 0):
    print("\n\n****DEFINITE DOMAIN NAMES****")

#Write domains to csv file
for domain in definiteDomainNames:
    print(domain)
    ofh.write(date + ',' + desc + ',' + "Domain" + ',' + domain + '\n')

if (len(maybeDomainNames) > 0):
    print("\n\n****POSSIBLE DOMAIN NAMES - CONSIDER ENTRY****")

#Possible domain names
for domain in maybeDomainNames:
    print(domain)
    #Upload "maybe" domain names to the spreadsheet, comment out/delete the following line to disable this
    ofh.write(date + ',' + desc + ',' + "Domain" + ',' + domain + ',,,Does NOT match official TLDs - please double-check\n')

if (len(domainNamesWhitelist) > 0):
    print("\n\n****DOMAIN NAMES IN WHITELIST****")

#Output whitelisted domain names:
for domain in domainNamesWhitelist:
    print(domain)
    
print("\n\nNon-whitelisted IOCs have been added to the spreadsheet.")
ofh.close()

input("Press enter to continue.")
