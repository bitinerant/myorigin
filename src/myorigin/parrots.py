from dataclasses import dataclass
from enum import Enum
import re
from sqlmodel import Field, Session, SQLModel, create_engine, select


flock_data = '''
# **Do not change or reuse parrot codes** (column 0)

# currently, each row can expand to 4 database rows (2 IP versions × http vs. https)

00 icanhazip.com/                            0 I J
01 ip1.dynupdate.no-ip.com/                  4 I
02 myip.dnsomatic.com/                       4 I J
03 smart-ip.net/myip                         0             # cannot connect
04 ipecho.net/plain                          4   J
05 ident.me/                                 0 I J M N     # https://api.ident.me/
06 tnedi.me/                                 0 I J M N     # https://ipa.tnedi.me/
07 ip.appspot.com/                           0             # 503 Service Unavailable
08 checkip.dyndns.org/                       4 I
09 www.lawrencegoetz.com/programs/ipinfo/    0             # no API
10 shtuff.it/myip/short/                     0             # cannot connect
11 ifconfig.me/ip                            4 I J
12 www.google.com/search?q=my+ip             0             # 403 Forbidden
13 bot.whatismyipaddress.com/                0             # API discontinued "due to massive abuse"
14 ipv4.ipogre.com/                          0             # Connection timeout
15 automation.whatismyip.com/n09230945.asp   0             # API discontinued?
16 myipis.net/                               0             # API discontinued?
17 www.ipchicken.com/                        4   J
18 myip.com.tw/                              4   J
19 httpbin.org/ip                            4 I J
20 ip.nf/me.txt                              4   J   N
21 am.i.mullvad.net/ip                       0   J
22 am.i.mullvad.net/json                     0       N     # https://mullvad.net/en/check/
23 zx2c4.com/ip                              0 I J
24 ip.websupport.sk/                         0 I J
25 www.ivpn.net/                             0   J
26 www.ipaddress.com/                        0             # API discontinued?
27 www.ipaddress.my/                         0   J
28 www.showmyip.com/                         0             # no API
29 ip-api.com/line/?fields=query             4 I
30 ip-api.com/json/?fields=16966359          0     M       # https://ip-api.com/docs/
31 api.ipify.org/                            4 I J
32 ifconfig.io/ip                            0 I J
33 ipaddress.sh/                             4 I J
34 api.iplocation.net/?ip={ip}               0       N     # https://api.iplocation.net/
35 ipinfo.io/ip                              4 I J
36 ipinfo.io/{ip}/json                       4       N
37 api.ipregistry.co/?key=tryout             0 I J   N     # https://ipregistry.co/docs/
38 myexternalip.com/raw                      4 I J
39 checkip.amazonaws.com/                    4 I J
40 diagnostic.opendns.com/myip               0             # cannot connect
41 whatismyip.akamai.com/                    0             # cannot connect
42 test-ipv6.com/ip/                         4 I J         # ironically, no IPv6 AAAA record
43 api.infoip.io/                            4 I J M N     # https://ciokan.docs.apiary.io/
44 checkip.dns.he.net/                       0 I J
45 ipapi.co/ip                               0   J
46 www.cloudflare.com/cdn-cgi/trace          0 I J
47 www.trackip.net/ip                        0 I J
48 www.trackip.net/ip?json                   0     M N
49 mypubip.com/                              0 I J
50 ip.seeip.org/                             0   J
51 ip.seeip.org/geoip                        0     M N
52 api.bigdatacloud.net/data/client-ip       4 I J
53 myip.opendns.com%20A%20@resolver1.opendns.com   0   D  
54 o-o.myaddr.l.google.com%20TXT%20@8.8.8.8        0   D  
55 whoami.akamai.net%20ANY%20@ns1-1.akamaitech.net 0   D  
'''


class Parrot(SQLModel, table=True):  # data for one interface of an API provider
    # (Parrots repeats what they hear. A my-IP API provider repeats the callers IP back to them.)
    id: int = Field(primary_key=True)
    ptask: str  # one of: 'I', 'J', 'D', 'S', 'M', 'N'
    ip_version: int  # always 4 or 6
    address: str  # host+path (URL without protocol)
    milliweight: int = 1000  # 2000 means 2x more likely to be used; 0 means disabled
    attempt_count: int = 0  # number of attempted connections
    success_count: int = 0  # number of valid IP addresses returned
    total_rtt: int = 0  # total rtt (in ms) for all successful attempts
    last_errmsg: str = ""

    class Ptask(Enum):
        IP_HTTP = 'I'  # get IP via http
        IP_HTTPS = 'J'  # get IP via https
        IP_DNS = 'D'  # get IP via DNS (not yet implemented)
        IP_STUN = 'S'  # get IP via STUN (not yet implemented)
        MD_HTTP = 'M'  # get IP metadata via http (not yet implemented)
        MD_HTTPS = 'N'  # get IP metadata via https (not yet implemented)

    @dataclass
    class ParrotFields:
        code: int  # unique id so we can safely copy future changes to user's DB
        address: str  # URL without 'https://' or 'http://'
        ip_version: int  # 0==both, 4==IPv4 only, 6==IPv6 only
        ptasks: list  # Ptask list

    @staticmethod
    def parrot_data() -> ParrotFields:
        for line in flock_data.split('\n'):
            wout_comments = re.sub(r'( +|^)#.*\n?', '', line)  # strip comments
            if len(wout_comments) == 0:
                continue
            fields = re.sub(r' +', ' ', wout_comments).split(' ')
            assert len(fields) >= 3, f"invalid flock_data line: {line}"
            yield Parrot.ParrotFields(
                code=fields[0],
                address=fields[1],
                ip_version=int(fields[2]),
                ptasks=fields[3:],
            )

    @staticmethod
    def startup(engine):
        with Session(engine) as session:
            for p in Parrot.parrot_data():
                # do not adjust the Ptask list here except to append; .id is computed from it
                for i, ptask in enumerate([Parrot.Ptask.IP_HTTP, Parrot.Ptask.IP_HTTPS]):
                    for v in (4, 6):  # IPv4, IPv6
                        ip_version_offset = 0 if v == 4 else 50  # IPv4 uses 0-49, IPv6 uses 50-99
                        id = 2018260000 + int(p.code) * 100 + ip_version_offset + i
                        statement = select(Parrot).where(Parrot.id == id)
                        result = session.exec(statement).one_or_none()
                        ptask_active = ptask.value in p.ptasks
                        ip_version_active = p.ip_version == 0 or p.ip_version == v
                        if result is None:  # no existing row in DB
                            if not (ptask_active and ip_version_active):
                                continue  # not in DB and shouldn't be
                            result = Parrot()  # add new row to database for this Ptask
                            result.id = id
                        else:  # existing row in DB
                            if not (ptask_active and ip_version_active):
                                result.milliweight = 0  # disable in DB
                            else:
                                result.milliweight = 1000  # make sure it is enabled
                        result.ptask = ptask.value
                        result.ip_version = v
                        result.address = p.address
                        session.add(result)
            session.commit()

    @staticmethod
    def acive_parrot_count():
        result = 0
        for p in Parrot.parrot_data():
            if Parrot.Ptask.IP_HTTP.value in p.ptasks or Parrot.Ptask.IP_HTTPS.value in p.ptasks:
                result += 1
        return result

    def url(self):
        if self.ptask == Parrot.Ptask.IP_HTTP.value:
            return 'http://' + self.address
        if self.ptask == Parrot.Ptask.IP_HTTPS.value:
            return 'https://' + self.address
        assert ValueError, f"Ptask {Parrot.Ptask(self.ptask).name} not yet implemented"

    def score(self):  # compute a score which will determine how likely it is to be chosen
        if self.attempt_count != 0:
            percent = 100.0 * self.success_count / self.attempt_count
        else:
            percent = 100.0
        score = round(percent**2 / 100.0)  # biggest portion of score is success rate
        score += 5  # every parrot gets a small chance of being selected
        if self.attempt_count < 10:
            score += 5  # prefer new parrots
        if self.success_count != 0:
            average_ms = 1.0 * self.total_rtt / self.success_count
            score += round(max((5000 - average_ms) / 400, 0.0))  # prefer faster parrots
        score *= self.milliweight  # normally 1000, but can be 0 to disable or more to promote
        return score

    @staticmethod
    def show_parrot_db(engine):
        with Session(engine) as session:
            to_show = dict()
            results = session.exec(select(Parrot))
            for p in results:
                score = p.score()
                disp = ""
                disp += f"ipv{p.ip_version}.{p.url()}:\n"
                if p.attempt_count != 0:
                    percent = round(100.0 * p.success_count / p.attempt_count)
                    disp += f"    {percent}% success rate"
                    disp += f" ({p.success_count} of {p.attempt_count})\n"
                else:
                    disp += f"    not yet attempted\n"
                if p.success_count != 0:
                    average_ms = round(1.0 * p.total_rtt / p.success_count)
                    disp += f"    {average_ms} ms average round trip time\n"
                if len(p.last_errmsg) > 0:
                    disp += f"    most recent error: {p.last_errmsg[:70]}\n"
                disp += f"    score: {round(score/1000):,} points\n"
                to_show[score * 1000000 + p.id] = disp  # sortable, unique key
            for p in dict(sorted(to_show.items(), reverse=True)):
                print(to_show[p], end="")
