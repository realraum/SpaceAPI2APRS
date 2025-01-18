from spacedirectory import directory, views, space
from geopy.geocoders import Nominatim
from aprspy import PositionPacket
from datetime import datetime
import aprslib
import hashlib


loc = Nominatim(user_agent="Geopy Library")


space_list = directory.get_spaces_list()


AIS = aprslib.IS("OE6FAX", passwd="19385",host="192.168.69.67" , port=14580, )
AIS.connect()

space_count = 0
name_to_long = 0

for keys in space_list.keys():
    try:
        current_space = directory.get_space_from_name(keys)

        try:
            longitude = current_space.location.longitude
            latitude = current_space.location.latitude

        except:

            try:
                getLoc = loc.geocode(current_space.location.address)
                longitude = getLoc.longitude
                latitude = getLoc.latitude
            except:
                print("Failed to convert address to coordinates")


        print(keys)
        hash = hashlib.sha1(keys.encode('utf-8')).hexdigest()
        print("Latitude:", str(latitude))
        print("Longitude:", str(longitude))

        space_count = space_count + 1

        try:
            message = PositionPacket()

            
            try:
                timestamp = current_space.status.last_change
                year = int(current_space.status.last_change.strftime("%Y"))

                try:
                    if (timestamp.strftime("%d") != datetime.utcnow().strftime("%d")):
                        timestamp = timestamp.strftime("%d. %b, %H:%M")
                    else:
                        timestamp = timestamp.strftime("%H:%M")
                except:
                    pass

                if (year >= 2025):
                    if (current_space.status.is_open):
                        message_string = "Open: " + str(timestamp)
                        message.symbol_table = "\\"
                        message.symbol_id = "-"

                    else:
                        message_string = "Closed: " + str(timestamp)
                        message.symbol_table = "/"
                        message.symbol_id = "-"
                else:
                    message_string = ""

            except:
                print("Error Time")
                message_string = ""
                message.symbol_table = "\\"
                message.symbol_id = "-"
                pass

            #website = current_space.status.Space.website
            #if (len(website) < 20):
            #    message_string = message_string + "  " + website



            if (len(keys) > 9):
                name_to_long = name_to_long + 1
                #message.source = "Hckspc-" + str(name_to_long)
                message.source = "Hckr-" + hash[:4]
                if (message_string == ""):
                    message.comment = ""
                else:
                    message.comment = keys + "; " + message_string
            else:
                message.source = keys
                message.comment = message_string

            message.destination = "APRS"
            message.path = "APRS"
            message.addressee = "OE6FAX"

            message.latitude = latitude
            message.longitude = longitude

            packet = message.generate()

            AIS.sendall(packet)

            print(packet)
            print("\n")

        except:
            print("APRS failed")


    except:
        pass
        #print("Failed to connect to hackerspace api")

print("\n\nSpace count:", str(space_count))
print("Name to long:", str(name_to_long))