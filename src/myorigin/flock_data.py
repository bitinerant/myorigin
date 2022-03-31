flock_data = '''
#field 0: unique parrot name
#field 1: address without http or https  
#field 2: ip_version (0 (both) or 4 or 6)
#field 3: protocol (p (http only) or s (https only) or b (both) or x (disabled))
#everything after # is a comment

# when making changes, be sure to increment flock_data_version
2ip.me                api.2ip.me/provider.json?ip=     0 x # 429 Too Many Requests
2ip.ru                2ip.ru/                          0 x # No IP address found
2ip.tools             2ip.tools/                       0 x # Cannot connect to host 2ip.tools:80 ...
2ip.ua                api.2ip.ua/geo.json?ip=          0 x # 429 Too Many Requests
42.pl                 ip.42.pl/                        4 b
66.171.248.178        66.171.248.178/                  0 x # Cannot connect to host 66.171.248.1 ...
7fw.de                7fw.de/ipraw.php                 4 b
89.39.105.12          89.39.105.12/ip.shtml            0 x # No IP address found
aboutmyip.com         aboutmyip.com/                   0 x # No IP address found
amazonaws.com         checkip.amazonaws.com/           4 b
am.i.mullvad.net      am.i.mullvad.net/ip              0 s
amulex.com            ip.amulex.com/                   0 x # No IP address found
anysrc.net            ip.anysrc.net/                   0 b
appspot.com           ip.appspot.com/                  0 x # 503 Service Unavailable
aruljohn.com          ip.aruljohn.com/json             0 s
avast.com             ip-info.ff.avast.com/            0 x # 404 Not Found
aws.a2z.com           checkip.check-ip.aws.a2z.com/    4 b
bahoot.com            bahoot.com/                      0 x # Connection timeout to host http://b ...
bearsmyip.com         disabled.bearsmyip.com/          0 x # Cannot connect to host disabled.bea ...
bigdatacloud.net      api.bigdatacloud.net/data/client-ip 4 b
cctv.pk               ip.cctv.pk/                      0 x # No IP address found
checkip.me            checkip.me/                      0 x # Cannot connect to host checkip.me:8 ...
checkip.net           checkip.net/                     4 s
checkip.org           checkip.org/                     4 b
checkip.pw            checkip.pw/                      0 x # Cannot connect to host checkip.pw:8 ...
checkmyip.com         checkmyip.com/                   0 x # Timeout on reading data from socket
check-my-ip.net       check-my-ip.net/                 0 x # Connection timeout to host http://c ...
chinaz.com            ip.chinaz.com/                   0 x # [Errno 104] Connection reset by peer
cloudflare.com        www.cloudflare.com/cdn-cgi/trace 0 b
cmyip.com             cmyip.com/                       0 x # Cannot connect to host cmyip.com:44 ...
cmyip.net             cmyip.net/                       0 x # Cannot connect to host cmyip.net:80 ...
codeluxsoftware.com   codeluxsoftware.com/             0 x # Cannot connect to host codeluxsoftw ...
crymyip.com           crymyip.com/                     4 s
curlmyip.com          curlmyip.com/                    0 x # Connection timeout to host http://c ...
curlmyip.net          curlmyip.net/                    0 b
dawhois.com           dawhois.com/my_ip_address.php    0 s
db-ip.com             api.db-ip.com/                   0 x # 302 Found
dnsdynamic.org        myip.dnsdynamic.org/             0 x # Cannot connect to host myip.dnsdyna ...
dns.he.net            checkip.dns.he.net/              0 b
dnsomatic.com         myip.dnsomatic.com/              4 b
dnswatch.info         www.dnswatch.info/what's-my-ip   0 x # No IP address found
dpool.sina.com.cn     dpool.sina.com.cn/               0 x # Connection timeout to host http://d ...
dramor.net            myip.dramor.net/                 0 x # 404 no such forward entry
dtdns.com             myip.dtdns.com/                  0 x # Cannot connect to host myip.dtdns.c ...
dyn.com               checkip.dyn.com/                 0 x # 502 Bad Gateway
dyndns.com            checkip.dyndns.com/              0 x # 502 Bad Gateway
dyndns.es             checkip.dyndns.es/               0 x # 403 Forbidden
dyndns.it             checkip.dyndns.it/               4 b
dyndns.org            checkip.dyndns.org/              4 p
dynupdate.no-ip.com   ip1.dynupdate.no-ip.com/         4 p
easylife.tw           myip.easylife.tw/                0 x # Connection timeout to host http://m ...
e-localizaip.com      e-localizaip.com/                0 x # Cannot connect to host e-localizaip ...
eth0.me               eth0.me/                         4 b
everdot.org           whatismyip.everdot.org/          0 x # Cannot connect to host whatismyip.e ...
extreme-ip-lookup.com extreme-ip-lookup.com/json/?key=demo2 4 b
findmyipaddress.com   findmyipaddress.com/             0 x # Connection timeout to host https:// ...
findmyip.org          findmyip.org/                    0 x # Timeout on reading data from socket
formyip.com           formyip.com/                     0 x # 403 Forbidden
freegeoip.app         freegeoip.app/                   0 x # No IP address found
freegeoip.live        freegeoip.live/xml/              0 s
game.qq.com           apps.game.qq.com/comm-htdocs/ip/get_ip.php 4 b
geodatatool.com       www.geodatatool.com/             4 s
geoip.co.uk           disabled.geoip.co.uk/            0 x # Cannot connect to host disabled.geo ...
geoip-db.com          geoip-db.com/                    0 x # Cannot connect to host geoip-db.com ...
geoiptool.com         geoiptool.com/                   0 x # Cannot connect to host geoiptool.co ...
geoip.vmn.net         geoip.vmn.net/                   0 x # No IP address found
geolocation-db.com    geolocation-db.com/json/         4 b
geoplugin.net         www.geoplugin.net/csv.gp         4 p
get.geojs.io          get.geojs.io/                    0 s
get-myip.com          get-myip.com/                    4 s
getmyip.co.uk         getmyip.co.uk/                   0 x # 302 Moved Temporarily
getmyip.org           getmyip.org/                     0 x # No IP address found
getmyip.win           getmyip.win/                     0 x # Cannot connect to host getmyip.win: ...
google.com            www.google.com/search?q=my+ip    0 x # 403 Forbidden
heltech.se            myip.heltech.se/                 4 b
herokussl.com         nagano-19599.herokussl.com       0 x # Cannot connect to host nagano-19599 ...
hostip.info           api.hostip.info/get_html.php     4 b
httpbin.org           httpbin.org/ip                   4 b
icanhazip.com         icanhazip.com/                   0 b
ident.me              ident.me/                        0 b # https://api.ident.me/
ifcfg.me              ifcfg.me/                        0 x # Cannot connect to host ifcfg.me:443 ...
ifconfig.co           ifconfig.co/                     0 b
ifconfig.io           ifconfig.io/ip                   0 b
ifconfig.me           ifconfig.me/ip                   4 b
ilmioip.it            ilmioip.it/                      0 x # 302 Found
indirizzo-ip.com      www.indirizzo-ip.com/IP-Whois.php 4 b
inet-ip.info          inet-ip.info/                    4 b
infoip.io             api.infoip.io/                   4 b # https://ciokan.docs.apiary.io/
ip138.com             disabled.ip138.com/              0 x # Cannot connect to host disabled.ip1 ...
ip-1.com              ip-1.com/                        0 x # Cannot connect to host ip-1.com:443 ...
ip2location.com       www.ip2location.com/             0 x # No IP address found
ip2nation.com         ip2nation.com/                   4 p
ip4.me                ip4.me/                          4 b
ip6.me                ip6.me/api/                      0 b
ip-addr.es            ip-addr.es/                      4 s
ip-address.cc         ip-address.cc/                   0 x # 302 Found
ipaddresscheck.com    www.ipaddresscheck.com/          0 x # 'utf-8' codec can't decode byte 0x9 ...
ipaddress.com         www.ipaddress.com/               0 x # API discontinued?
ipaddress.my          www.ipaddress.my/                0 s
ipaddress.net         ipaddress.net/                   0 x # No IP address found
ipaddress.org         disabled.ipaddress.org/          0 x # Cannot connect to host disabled.ipa ...
ip-address.ru         ip-address.ru/                   0 x # No IP address found
ipaddress.sh          ipaddress.sh/                    4 b
ipaddressworld.com    ipaddressworld.com/              0 x # 403 Forbidden
ip-adress.com         www.ip-adress.com/what-is-my-ip-address 0 x # No IP address found
ip-adress.eu          www.ip-adress.eu/                0 b
ipapi.co              ipapi.co/ip                      0 s
ip-api.com            ip-api.com/line/?fields=query    4 p
ipchecker.info        ipchecker.info/                  0 x # 302 Found
ip-check.info         ip-check.info/                   0 x # Cannot connect to host ip-check.inf ...
ipchicken.com         www.ipchicken.com/               4 s
ip.cn                 www.ip.cn/                       0 x # No IP address found
ipcode.pw             ipcode.pw/                       0 x # Only 0 bytes received
ip-detect.net         ip-detect.net/                   0 x # Cannot connect to host ip-detect.ne ...
ipecho.net            ipecho.net/plain                 4 b
ipify.org             api.ipify.org/                   4 b
ipinfodb.com          www.ipinfodb.com/                0 b
ipinfo.info           api.ipapi.com/api/?access_key=   0 x # No IP address found
ipinfo.io             ipinfo.io/ip                     4 b
ip-info.org           ip-info.org/                     0 x # 307 Temporary Redirect
ip-info.xyz           ip-info.xyz/                     0 x # Timeout on reading data from socket
ipip.net              myip.ipip.net/                   4 b
ipleak.net            ipleak.net/                      0 b
iplocation.net        iplocation.net/                  0 x # No IP address found
iplogger.org          iplogger.org/myip/               0 x # No IP address found
iplogger.ru           iplogger.ru/us/myip/             0 x # No IP address found
ipmonkey.com          ipmonkey.com/                    4 p
ip.nf                 ip.nf/me.txt                     4 s
ipof.in               ipof.in/txt                      0 s
ipogre.com            ipv4.ipogre.com/                 0 x # Connection timeout
ip-ping.ru            www.ip-ping.ru/                  0 x # 'utf-8' codec can't decode byte 0xd ...
ipregistry.co         api.ipregistry.co/?key=tryout    0 b # https://ipregistry.co/docs/
ip.sb                 api.ip.sb/ip                     0 b # https://ip.sb/api/
ip-score.com          ip-score.com/ip                  4 s # https://ip-score.com/api
ip-secrets.com        www.ip-secrets.com/              0 x # 'utf-8' codec can't decode byte 0xa ...
ipstack.com           ipstack.com/                     0 s
iptrackeronline.com   www.iptrackeronline.com/         0 s
ipv6-test.com         ipv6-test.com/api/myip.php       0 b
ip-who-is.com         ip-who-is.com/                   0 x # Cannot connect to host ip-who-is.co ...
ip-whois.net          ip-whois.net/                    0 x # 'utf-8' codec can't decode byte 0xc ...
israel.net            myip.israel.net/                 0 x # 302 Found
ivpn.net              www.ivpn.net/                    0 s
jacware.com           myip.jacware.com/                0 x # Cannot connect to host myip.jacware ...
j.maxmind.com         j.maxmind.com/                   0 x # Cannot connect to host j.maxmind.co ...
jsonip.com            jsonip.com/                      0 s
keliweb.it            keliweb.it/mioip.php             0 x # 403 Forbidden
l2.io                 l2.io/ip.json                    4 b
lawrencegoetz.com     www.lawrencegoetz.com/programs/ipinfo/ 4 p
localizaip.com.br     localizaip.com.br/               0 x # Cannot connect to host localizaip.c ...
meip.eu               meip.eu/                         4 s
meuip.net.br          meuip.net.br/                    4 s
mioip.biz             mioip.biz/                       4 s
mioip.ch              mioip.ch/                        4 p
mioip.info            mioip.info/                      4 b
mio-ip.it             www.mio-ip.it/                   0 x # No IP address found
mioip.it              mioip.it/                        4 b
mioip.org             mioip.org/                       0 x # Cannot connect to host mioip.org:80 ...
mioip.win             mioip.win/                       0 x # 526 
moanmyip.com          www.moanmyip.com/                0 s
mon-ip.com            www.mon-ip.com/info-adresse-ip.php 0 x # 403 Forbidden
mudfish.net           myip.mudfish.net/                4 b
mycamip.com           www.mycamip.com/                 0 s
myexternalip.com      myexternalip.com/raw             4 b
myglobalip.com        myglobalip.com/                  0 x # Cannot connect to host myglobalip.c ...
myipaddress.com       www.myipaddress.com/             0 b
my-ip-address.co      www.my-ip-address.co/            0 s
my-ip-address.net     disabled.my-ip-address.net       0 x # Cannot connect to host disabled.my- ...
myip.am               myip.am/                         0 x # No IP address found
myip.by               myip.by/                         0 x # Cannot connect to host myip.by:80 s ...
myip.cc               disabled.myip.cc/                0 x # Cannot connect to host disabled.myi ...
myip.cf               myip.cf/                         0 s
myip.ch               myip.ch/                         0 x # Cannot connect to host myip.ch:443  ...
my-ip.club            my-ip.club/                      0 x # Cannot connect to host my-ip.club:4 ...
myip.cn               myip.cn/                         0 x # Cannot connect to host myip.cn:80 s ...
myip.co.il            myip.co.il/                      4 p
myip.com              api.myip.com/                    0 s
myip.com.br           myip.com.br/                     0 x # No IP address found
myip.com.tw           myip.com.tw/                     4 s
myip.com.ua           myip.com.ua/                     0 x # Found non-global IP address 127.0.0.1
myip.co.nz            myip.co.nz/                      0 x # Cannot connect to host myip.co.nz:8 ...
myip.cz               myip.cz/                         4 s
myip.dk               disabled.myip.dk/                0 x # Cannot connect to host disabled.myi ...
myip.es               myip.es/mi-ip                    0 x # 403 Forbidden
myip.eu               myip.eu/                         0 x # No IP address found
myip.fi               myip.fi/                         4 s
myip.gratis           myip.gratis/                     0 x # Cannot connect to host myip.gratis: ...
myip.gr               disabled.myip.gr/                0 x # Cannot connect to host disabled.myi ...
myip.ht               myip.ht/                         0 b
myip.info             ipv6.myip.info/                  6 s
myipinfo.net          myipinfo.net/                    0 x # 403 Forbidden
my-ip.io              api.my-ip.io/ip                  0 s # https://www.my-ip.io/api
myip.io               disabled.myip.io/                0 x # Cannot connect to host disabled.myi ...
myip.is               myip.is/                         0 x # 'utf-8' codec can't decode byte 0xd ...
myipis.net            myipis.net/                      0 x # No IP address found
myip.knet.ca          myip.knet.ca/                    4 s
myip.kz               myip.kz/                         4 s
myip.ma               myip.ma/                         4 b
myip.ms               api.myip.ms/ip                   0 x # No IP address found
myip.mx               myip.mx/                         0 x # Connection timeout to host https:// ...
myip.net              myip.net/                        0 x # Connection timeout to host http://m ...
myip.nl               myip.nl/                         4 b
myipnow.com           myipnow.com/                     4 s
myipnumber.com        myipnumber.com/                  4 p
myip.nu               myip.nu/                         0 x # No IP address found
myiponline.com        myiponline.com/                  0 x # Connection timeout to host http://m ...
myip.report           myip.report/                     0 x # No IP address found
myip.ru               myip.ru/                         0 x # No IP address found
myip.se               myip.se/                         0 x # 403 Forbidden
myip.si               myip.si/                         0 x # No IP address found
myip.tk               myip.tk/                         0 x # Cannot connect to host myip.tk:80 s ...
myip.tw               myip.tw/                         0 x # No IP address found
myip.wtf              text.myip.wtf/                   0 b
myip.zone             disabled.myip.zone/              0 x # Cannot connect to host disabled.myi ...
mylnikov.org          disabled.mylnikov.org/           0 x # Connection timeout to host http://d ...
mylocation.org        mylocation.org/                  4 s
mysau.com.au          myip.mysau.com.au/               4 b
my-proxy.com          www.find-ip.net/                 4 b
mypubip.com           mypubip.com/                     0 b
narak.com             checkip.narak.com/               0 x # Cannot connect to host checkip.nara ...
network-tools.com     network-tools.com/               0 x # No IP address found
nmonitoring.com       myip.nmonitoring.com/            0 x # No IP address found
northstate.net        myip.northstate.net/             4 p
opendns.com           myip.opendns.com/                0 x # Cannot connect to host myip.opendns ...
ozymo.com             myip.ozymo.com/                  0 x # No IP address found
qualmeuip.com.br      qualmeuip.com.br/meuip/          0 x # Timeout on reading data from socket
readip.info           readip.info/                     0 x # No IP address found
rest7.com             api.rest7.com/v1/my_ip.php       4 p
rs.sr                 myip.rs.sr/                      4 s
sdu.dk                myip.sdu.dk/                     4 s
searchenginereports.net searchenginereports.net/what-is-my-ip 0 x # No IP address found
seeip.org             ip.seeip.org/                    0 s
sfml-dev.org          www.sfml-dev.org/ip-provider.php 4 p
shmyip.com            shmyip.com/                      0 x # Connection timeout to host https:// ...
shorty.org            myip.shorty.org/                 0 x # Cannot connect to host myip.shorty. ...
show-ip.com           show-ip.com/                     0 x # No IP address found
showipinfo.net        showipinfo.net/                  0 x # Cannot connect to host showipinfo.n ...
showip.net            showip.net/                      4 b
showmemyip.com        www.showmemyip.com/              4 s
showmyipaddress.com   www.showmyipaddress.com/         0 x # No IP address found
showmyipaddress.eu    wwww.showmyipaddress.eu/         0 x # Cannot connect to host wwww.showmyi ...
showmyip.com.ar       www.showmyip.com.ar/             0 p
showmyip.com          www.showmyip.com/                4 s
showmyip.co.uk        disabled.showmyip.co.uk/         0 x # Cannot connect to host disabled.sho ...
show-my-ip.de         www.show-my-ip.de/ipadresse/     0 x # Timeout on reading data from socket
showmyip.gr           www.showmyip.gr/                 0 s
showmyipnow.com       showmyipnow.com/                 0 x # Cannot connect to host showmyipnow. ...
shtuff.it             shtuff.it/myip/short/            0 x # Cannot connect to host shtuff.it:80 ...
smart-ip.net          smart-ip.net/myip                0 x # Connection timeout to host http://s ...
surfeasy.com          myip.surfeasy.com/               0 x # Cannot connect to host myip.surfeas ...
sypexgeo.net          api.sypexgeo.net/                4 b
taobao.com            ip.taobao.com/                   0 x # No IP address found
telespex.com          myip.telespex.com/               0 x # 302 Moved Temporarily
telize.com            ip.telize.com/                   0 x # Cannot connect to host ip.telize.co ...
tell-my-ip.com        disabled.tell-my-ip.com/         0 x # No IP address found
test-ipv6.com         test-ipv6.com/ip/                4 b # ironically, no IPv6 AAAA record
thesafety.us          thesafety.us/check-ip            0 x # No IP address found
tnedi.me              tnedi.me/                        0 b # https://ipa.tnedi.me/
tnx.nl                tnx.nl/ip                        0 b
tool.la               ip.tool.la/                      0 x # Connection timeout to host http://i ...
toolsyep.com          toolsyep.com/en/what-is-my-ip/   0 x # No IP address found
tracemyip.com         tracemyip.com/                   4 s
tracemyip.org         www.tracemyip.org/               0 x # No IP address found
trackip.net           www.trackip.net/ip               0 b
tunnelbear.com        www.tunnelbear.com/whats-my-ip   0 x # No IP address found
tyk.nu                ip.tyk.nu/                       0 b
ua.edu                myip.ua.edu/                     0 x # Connection timeout to host http://m ...
uconn.edu             myip.uconn.edu/                  0 x # Cannot connect to host myip.uconn.e ...
ultratools.com        ultratools.com/                  0 x # 302 Found
urls.is               ip.urls.is/                      4 p
utrace.de             utrace.de/                       0 x # Connection timeout to host https:// ...
v6shell.org           myip.v6shell.org/                0 x # Cannot connect to host myip.v6shell ...
vermiip.es            vermiip.es/                      4 b
viewmyip.eu           viewmyip.eu/                     4 s
vinflag.com           vinflag.com/                     0 x # No IP address found
webmasterhome.cn      ip.webmasterhome.cn/             0 x # Connection timeout to host http://i ...
websupport.sk         ip.websupport.sk/                0 b
wgetip.com            wgetip.com/                      0 b
whatismybrowser.com   www.whatismybrowser.com/         0 x # No IP address found
whatismyipaddress.com bot.whatismyipaddress.com/       0 x # discontinued "due to massive abuse"
whatismyip.akamai.com whatismyip.akamai.com/           4 p
whatismyip.ca         whatismyip.ca/                   0 x # Cannot connect to host whatismyip.c ...
whatismyip.com        automation.whatismyip.com/n09230945.asp 0 x # API discontinued?
whatismyip.com.br     whatismyip.com.br/               0 x # 403 Forbidden
whatismyip.li         disabled.whatismyip.li/home      0 x # Cannot connect to host disabled.wha ...
whatismyip.net        www.whatismyip.net/              0 x # No IP address found
whatismyip.org        www.whatismyip.org/my-ip-address 0 s
whatismypublicip.com  www.whatismypublicip.com/        4 s
whatmyip.us           whatmyip.us/                     0 x # Cannot connect to host whatmyip.us: ...
whatsmyipaddress.com  whatsmyipaddress.com/            0 x # No IP address found
whatsmyipaddress.net  whatsmyipaddress.net/            0 x # No IP address found
whats-my-ip-address.org whats-my-ip-address.org/       0 x # 302 Found
w.hatsmyip.com        w.hatsmyip.com/                  0 x # Cannot connect to host w.hatsmyip.c ...
whatsmyip.ie          whatsmyip.ie/                    4 b
whatsmyip.net         whatsmyip.net/                   0 b
whatsmyip.org         www.whatsmyip.org/               0 x # Connection timeout to host http://w ...
whatsmyip.us          whatsmyip.us/                    0 x # Cannot connect to host whatsmyip.us ...
whatsmyip.website     whatsmyip.website/               0 x # 302 Found
whereisip.net         disabled.whereisip.net/          0 x # No IP address found
whoer.me              whoer.me/                        0 x # No IP address found
whoer.net             whoer.net/                       4 s
whoisping.com         whoisping.com/                   0 x # No IP address found
wipmania.com          api.wipmania.com/                0 x # Cannot connect to host api.wipmania ...
wtfismyip.com         wtfismyip.com/text               0 b
xmyip.com             www.xmyip.com/                   4 s
yougetsignal.com      www.yougetsignal.com/what-is-my-ip-address/ 4 s
youip.net             youip.net/                       4 s
your-ip-address.com   your-ip-address.com/             4 b
your-ip-fast.com      your-ip-fast.com/                0 x # Cannot connect to host your-ip-fast ...
yourip.us             www.yourip.us/                   0 x # 302 Found
zx2c4.com             zx2c4.com/ip                     0 b
'''
