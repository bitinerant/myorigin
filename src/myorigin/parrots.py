from dataclasses import dataclass
from enum import Enum
import logging
import re
from sqlmodel import Field, Session, SQLModel, create_engine, select


class Parrot(SQLModel, table=True):  # data for one interface of an API provider
    # (Parrots repeats what they hear. A my-IP API provider repeats the caller's IP back to them.)
    id: str = Field(primary_key=True)  # e.g. "0b.ipapi.co"; {ip_version}{proto}.{parrot_name}
    address: str = ""  # host+path (URL without protocol)
    milliweight: int = 1000  # 2000 means 2x more likely to be used; 0 means disabled
    attempt_count: int = 0  # number of attempted connections
    success_count: int = 0  # number of valid IP addresses returned
    total_rtt: int = 0  # total rtt (in ms) for all successful attempts
    last_errmsg: str = ""

    def ip_version(self) -> int:  # always 4 or 6
        return int(self.id[0])

    def proto(self) -> str:  # always 'p' (http) or 's' (https)
        return self.id[1]

    def url(self):
        if self.proto() == 'p':
            return 'http://' + self.address
        if self.proto() == 's':
            return 'https://' + self.address
        assert ValueError, f"Not yet implemented"

    @dataclass
    class ParrotFields:
        name: int  # unique name so we can safely copy future changes to user's DB
        address: str  # URL without 'https://' or 'http://'
        ip_version: int  # 0==both, 4==IPv4 only, 6==IPv6 only
        proto: str  # p==http only, s==https only, b==both, x==disabled

    @staticmethod
    def parrot_data(flock_data: str) -> ParrotFields:
        for line in flock_data.split('\n'):
            wout_comments = re.sub(r'( +|^)#.*\n?', '', line)  # strip comments
            if len(wout_comments) == 0:
                continue
            fields = re.sub(r' +', ' ', wout_comments).split(' ')
            assert len(fields) == 4, f"invalid flock_data line: {line}"
            assert fields[2] in ('0', '4', '6'), f"invalid flock_data line: {line}"
            assert fields[3] in ('p', 's', 'b', 'x'), f"invalid flock_data line: {line}"
            yield Parrot.ParrotFields(
                name=fields[0],
                address=fields[1],
                ip_version=int(fields[2]),
                proto=fields[3],
            )

    @staticmethod
    def startup(engine):
        with Session(engine) as session:
            statement = select(Parrot).where(Parrot.id == '4p.__version__')
            record = session.exec(statement).one_or_none()
            flock_data_version = 'v10094'  # add 1 when a change is made to flock_data.py
            if record and record.address >= flock_data_version:  # database is up-to-date
                return
            logger = logging.getLogger('myorigin')
            if record is not None:
                msg = "updating flock_data_version"
                logger.debug(f"{msg} from {record.address} to {flock_data_version}")
            else:
                logger.debug(f"updating flock_data_version from (none) to {flock_data_version}")
            if record is None:
                record = Parrot()
                record.id = '4p.__version__'
                record.milliweight = 0  # ensure we don't try to connect
            record.address = flock_data_version
            session.add(record)
            if hasattr(Parrot.startup, 'pytest'):  # mock responses; see myorigin_test.py
                flock_data = Parrot.startup.pytest
            else:
                from .flock_data import flock_data
            for row in Parrot.parrot_data(flock_data):  # one row in flock_data text
                for v in (4, 6):  # IPv4, IPv6
                    for p in ('p', 's'):  # http, https
                        id = f'{v}{p}.{row.name}'
                        proto_active = row.proto == p or row.proto == 'b'
                        ip_version_active = row.ip_version == 0 or row.ip_version == v
                        statement = select(Parrot).where(Parrot.id == id)
                        record = session.exec(statement).one_or_none()
                        if record is None:  # no existing record in DB
                            if not (proto_active and ip_version_active):
                                continue  # no need to add disabled records
                            record = Parrot()  # add new record to database
                            record.id = id
                            logger.debug(f"adding record {id}")
                        if proto_active and ip_version_active:
                            record.milliweight = 1000  # enable in case it was previously disabled
                        else:
                            record.milliweight = 0  # disable in DB
                        if record.address != row.address and record.address != "":
                            msg = f"updating record {id}"
                            logger.debug(f"{msg} from {record.address} to {row.address}")
                        record.address = row.address
                        session.add(record)
            session.commit()

    @staticmethod
    def acive_parrot_count():
        total = 0
        if True:
            from .flock_data import flock_data
        for p in Parrot.parrot_data(flock_data):
            if p.proto in ('p', 's', 'b'):
                total += 1
        return total

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

    def del_keys_of_same_parrot(self, scores_dict, logger=None):
        p_name = self.id[3:]  # parrot name without ip_version, proto
        ids_to_del = [k for k in scores_dict.keys() if k[3:] == p_name]
        if logger:
            logger.debug(f"removing {', '.join(ids_to_del)}")
        for k in ids_to_del:  # eliminate all IDs from same flock_data line, e.g.
            del scores_dict[k]  # don't check both http://ident.me and https://ident.me

    @staticmethod
    def show_parrot_db(engine):
        with Session(engine) as session:
            to_show = dict()
            results = session.exec(select(Parrot))
            for record in results:
                score = record.score()
                if score <= 0:
                    continue  # don't display disabled records
                disp = ""
                disp += f"ipv{record.ip_version()}.{record.url()}:\n"
                if record.attempt_count != 0:
                    percent = round(100.0 * record.success_count / record.attempt_count)
                    disp += f"    {percent}% success rate"
                    disp += f" ({record.success_count} of {record.attempt_count})\n"
                else:
                    disp += f"    not yet attempted\n"
                if record.success_count != 0:
                    average_ms = round(1.0 * record.total_rtt / record.success_count)
                    disp += f"    {average_ms} ms average round trip time\n"
                if len(record.last_errmsg) > 0:
                    disp += f"    most recent error: {record.last_errmsg[:70]}\n"
                disp += f"    score: {round(score/1000):,} points\n"
                to_show[f'{score:08}.{record.id}'] = disp  # sortable, unique key
            for key in dict(sorted(to_show.items(), reverse=True)):
                print(to_show[key], end="")
