# SubscribersFinder
Finding BNGs/LNS PPP Subscribers with errors during migration windows

The script detects subscribers with errors and that cannot be authenticated by RADIUS, basically the list of the commands is defined in commands.txt, you can define new commands if you want to customize it or run someother checks.

The list of the device is define in the inventory.json.

In some cases there are subscribers that authentication are failing for different reasons and can make noise during the migration windows and can be defined in the KnownFailedUsers.txt and also in the BGPFailedUsers.txt to be ignored.

At the end the scripts generate the DEVICE_output.txt file for each device to report the possible errors.
