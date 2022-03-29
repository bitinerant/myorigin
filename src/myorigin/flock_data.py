flock_data = '''
#field 0: unique parrot name
#field 1: address without http or https  
#field 2: ip_version (0 (both) or 4 or 6)
#field 3: protocol (p (http only) or s (https only) or b (both) or x (disabled))
#everything after # is a comment

# when making changes, be sure to increment flock_data_version
amazonaws.com         checkip.amazonaws.com/           4 b
am.i.mullvad.net      am.i.mullvad.net/ip              0 s
appspot.com           ip.appspot.com/                  0 x # 503 Service Unavailable
bigdatacloud.net      api.bigdatacloud.net/data/client-ip 4 b
cloudflare.com        www.cloudflare.com/cdn-cgi/trace 0 b
dns.he.net            checkip.dns.he.net/              0 b
dnsomatic.com         myip.dnsomatic.com/              4 b
dyndns.org            checkip.dyndns.org/              4 p
dynupdate.no-ip.com   ip1.dynupdate.no-ip.com/         4 p
google.com            www.google.com/search?q=my+ip    0 x # 403 Forbidden
httpbin.org           httpbin.org/ip                   4 b
icanhazip.com         icanhazip.com/                   0 b
ident.me              ident.me/                        0 b # https://api.ident.me/
ifconfig.io           ifconfig.io/ip                   0 b
ifconfig.me           ifconfig.me/ip                   4 b
infoip.io             api.infoip.io/                   4 b # https://ciokan.docs.apiary.io/
ipaddress.com         www.ipaddress.com/               0 x # API discontinued?
ipaddress.my          www.ipaddress.my/                0 s
ipaddress.sh          ipaddress.sh/                    4 b
ipapi.co              ipapi.co/ip                      0 s
ip-api.com            ip-api.com/line/?fields=query    4 p
ipchicken.com         www.ipchicken.com/               4 s
ipecho.net            ipecho.net/plain                 4 s
ipify.org             api.ipify.org/                   4 b
ipinfo.io             ipinfo.io/ip                     4 b
ip.nf                 ip.nf/me.txt                     4 s
ipogre.com            ipv4.ipogre.com/                 0 x # Connection timeout
ipregistry.co         api.ipregistry.co/?key=tryout    0 b # https://ipregistry.co/docs/
ivpn.net              www.ivpn.net/                    0 s
lawrencegoetz.com     www.lawrencegoetz.com/programs/ipinfo/ 0 x # no API
myexternalip.com      myexternalip.com/raw             4 b
myip.com.tw           myip.com.tw/                     4 s
myipis.net            myipis.net/                      0 x # API discontinued?
mypubip.com           mypubip.com/                     0 b
opendns.com           diagnostic.opendns.com/myip      0 x # cannot connect
seeip.org             ip.seeip.org/                    0 s
showmyip.com          www.showmyip.com/                0 x # no API
shtuff.it             shtuff.it/myip/short/            0 x # cannot connect
smart-ip.net          smart-ip.net/myip                0 x # cannot connect
test-ipv6.com         test-ipv6.com/ip/                4 b # ironically, no IPv6 AAAA record
tnedi.me              tnedi.me/                        0 b # https://ipa.tnedi.me/
trackip.net           www.trackip.net/ip               0 b
websupport.sk         ip.websupport.sk/                0 b
whatismyipaddress.com bot.whatismyipaddress.com/       0 x # "due to massive abuse"
whatismyip.akamai.com whatismyip.akamai.com/           0 x # cannot connect
whatismyip.com        automation.whatismyip.com/n09230945.asp 0 x # API discontinued?
zx2c4.com             zx2c4.com/ip                     0 b
'''
