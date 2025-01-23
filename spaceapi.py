import sys

from spacedirectory import tools
from geopy.geocoders import Nominatim
from aprspy import PositionPacket
from datetime import datetime, timedelta
import aprslib
import hashlib
import argparse
import logging
from log import setup_custom_logger

setup_custom_logger()
logger = logging.getLogger('root')

aprs_is_server: str = "rotate.aprs2.net"
aprs_is_call: str = "N0CALL"
aprs_is_passwd: str = ""
aprs_is_client: aprslib.IS
aprs_dry_run: bool = False

aprs_msg_max_len = 67


class Space:
    name: (str | None)
    lat: (float | None)
    lon: (float | None)
    status: (bool | None)
    last_seen: (datetime | None)
    url: (str | None)

    def __init__(self):
        self.name = None
        self.lon = None
        self.lat = None
        self.status = None
        self.last_seen = None
        self.url = None  # optional

    def valid(self) -> bool:
        if self.name is not None \
                and self.lon is not None \
                and self.lat is not None \
                and self.status is not None \
                and self.last_seen is not None:
            return True
        else:
            return False


def get_aprs_symbol(open_closed: bool) -> (str, str):
    if open_closed:
        return "\\", "-"
    else:
        return "/", '-'


def send_space_to_aprs(space: Space):
    message = PositionPacket()

    # Relevant dynamic info for APRS packet
    aprs_source: str = ""
    aprs_alt_name: str = space.name
    aprs_space_status: str = f"[{'OPEN' if space.status is True else 'CLOSED'}]"
    aprs_symbol: (str, str) = get_aprs_symbol(space.status)
    aprs_last_seen: str = ""

    # Shorten Name if too long,
    hash = hashlib.sha1(space.name.encode('utf-8')).hexdigest()  # TODO: this might create hash collisions ??
    aprs_source = f"Hckr-{hash[:4]}"
    aprs_alt_name = space.name

    # Only show last seen for spaces open during the last year
    if datetime.now() - space.last_seen <= timedelta(days=365):
        # Shorten last seen for spaces seen today
        if datetime.now().strftime('%d') == space.last_seen.strftime('%d'):
            aprs_last_seen = space.last_seen.strftime('%H:%M')
        else:
            aprs_last_seen = space.last_seen.strftime('%Y-%m-%d %H:%M')

    message.symbol_table = aprs_symbol[0]
    message.symbol_id = aprs_symbol[1]
    message.source = aprs_source
    message.destination = "APRS"
    message.path = "APRS"
    message.addressee = aprs_is_call
    message.longitude = space.lon
    message.latitude = space.lat
    message.comment = f"{aprs_alt_name}{' ' if len(aprs_alt_name) > 0 else ''}{aprs_space_status} {aprs_last_seen}"

    msg_len = len(message.comment)
    logger.info(f"comment length: {msg_len}")
    if msg_len > aprs_msg_max_len:
        logger.critical(f"APRS comment too long '{message.comment}'")  # this should not happen
        sys.exit(-1)
    else:
        # optionally add space url if there's space in the comment
        if msg_len + len(space.url) + 1 <= aprs_msg_max_len:
            message.comment = message.comment + ' ' + space.url

    packet = message.generate()

    # TODO: rate limit?
    if not aprs_dry_run:
        aprs_is_client.sendall(packet)
    else:
        print(packet)


def send_space(space_json):
    space_data = None
    space = Space()

    try:
        space_data = space_json['data']
    except KeyError:
        try:
            logger.warning(f"Space api {space_json['url']} did not provide data")
            return
        except KeyError:
            logger.error(f"json error, missing field 'url': {space_json}")
            return

    try:
        space.name = space_data['space']
    except KeyError:
        logger.critical(f"Space has no name: {space_json}")
        return

    try:
        space.last_seen = datetime.fromtimestamp(space_json['lastSeen'])
    except KeyError:
        logger.warning(f"Space '{space.name}' has no lastSeen")
        return

    try:
        space.status = space_data['state']['open']
    except KeyError:
        logger.warning(f"Space '{space.name}' has no open/closed state")
        return

    loc = None
    try:
        loc = space_data['location']
    except KeyError:
        logger.warning(f"Space '{space.name}' did not provide location info")
        return

    try:
        space.lon = loc['lon']
        space.lat = loc['lat']
    except KeyError:
        logger.info(f"Space '{space.name}' did not provice LAT/LON info, trying via address")
        try:
            addr = loc['address']
            getLoc = loc.geocode(addr)
            if getLoc:
                space.lon = getLoc.longitude
                space.lat = getLoc.latitude
            else:
                logger.warning(f"Space '{space.name}': could not resolve address '{addr}' to coordinates")
                return
        except KeyError:
            logger.warning(f"Space '{space.name}' did not address info")
            return

    try:
        space.url = space_data['url']
    except KeyError:
        logger.info(f"Space '{space.name}' has no url")

    if space.valid():
        logger.info(f"Sending space '{space.name}' via APRS")
        send_space_to_aprs(space)


def main():
    global aprs_is_server, aprs_is_call, aprs_is_passwd, aprs_is_client, aprs_dry_run
    parser = argparse.ArgumentParser(description="Send SpaceAPI (Hackerspace status + names + locations) information "
                                                 "via APRS-IS.")
    parser.add_argument('-v', '--verbose', type=int, dest='verbose', help="verbosity level")
    parser.add_argument('-c', '--call', dest='callsign', help="'Uploader' callsign")
    parser.add_argument('-p', '--passwd', dest='passwd', help="'Uploader' password for APRS-IS")
    parser.add_argument('-s', '--server', dest='server',
                        help=f"APRS-IS server [default: {aprs_is_server}]")
    parser.add_argument('-n', '--dry-run', action='store_true', dest='dry',
                        help='dry run, do not send to APRS-IS')

    args = parser.parse_args()

    if args.verbose:
        if args.verbose <= 5 and args.verbose >= 0:
            level = logging.CRITICAL - int(args.verbose) * 10
            logger.setLevel(level)
        else:
            print("ERROR: stdout verbosity level must be between 0 and 5")
            sys.exit()
    else:
        logger.setLevel(logging.WARNING)
    if args.callsign:
        aprs_is_call = args.callsign
    else:
        print("Must give callsign")
        sys.exit()
    if args.passwd:
        aprs_is_passwd = args.passwd
    else:
        print("Must give APRS-IS password")
    if args.server:
        aprs_is_server = args.server
    if args.dry:
        aprs_dry_run = True

    if not aprs_dry_run:
        aprs_is_client = aprslib.IS(callsign=aprs_is_call, passwd=aprs_is_passwd, host=aprs_is_server, port=14580)
        try:
            aprs_is_client.connect()
        except aprslib.exceptions.ConnectionError as e:
            logger.critical(f"Could not connect to {aprs_is_server} as {aprs_is_call} ({aprs_is_passwd}), {e}")
            sys.exit(-1)

    location_service = Nominatim(user_agent="Geopy Library")
    all_hackspaces = tools.get_json_data_from_url("https://api.spaceapi.io/")
    logger.info(f"Found {len(all_hackspaces)} spaces in SpaceAPI")

    for space in all_hackspaces:
        send_space(space)


if __name__ == '__main__':
    main()