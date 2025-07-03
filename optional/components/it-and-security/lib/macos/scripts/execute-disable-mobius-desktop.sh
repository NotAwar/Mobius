#!/bin/sh


# execute.disable.mobius.desktop @2024 Mobius Device Management
# Brock Walters (brock@mobiusmdm.com)


# variables
dskplst='/Library/LaunchDaemons/com.mobius.disable.desktop.plist'
dskscpt='/private/tmp/disable.mobius.desktop.sh'
fltplst='/Library/LaunchDaemons/com.mobiusmdm.orbit.plist'


# check Mobius Desktop, exit if not enabled
if /usr/libexec/PlistBuddy -c 'print EnvironmentVariables:ORBIT_MOBIUS_DESKTOP' "$fltplst" | /usr/bin/grep -iq 'false'
then
    printf "Mobius Desktop is not enabled on this host. Exiting...\n"; exit
else
    printf "Disabling Mobius Desktop...\n"
fi


printf "Writing out disable Mobius Desktop script...\n"
/bin/cat << 'EOF' > "$dskscpt"
#!/bin/sh

# logging
cpuname="$(/usr/sbin/scutil --get ComputerName)"
srlnmbr="$(/usr/libexec/PlistBuddy -c 'print 0:serial-number' /dev/stdin <<< "$(/usr/sbin/ioreg -ar -d 1 -k 'IOPlatformSerialNumber')")"
usrcrnt="$(/usr/bin/stat -f %Su /dev/console)"
logexec="$(/usr/bin/basename "$0")"
logpath="/private/var/log/${logexec%.*}.log"
logpipe="/private/tmp/${logexec%.*}.pipe"

/usr/bin/mkfifo "$logpipe"
/usr/bin/tee -a < "$logpipe" "$logpath" &
exec &> "$logpipe"
printf "$(/bin/date "+%Y-%m-%dT%H:%M:%S") [START] logging %s\n   computer name: %s\n   serial number: %s\n   current user: %s\n" "$logexec" "$cpuname" "$srlnmbr" "$usrcrnt"  >> "$logpath"

logalrt(){
>&2 printf "$(/bin/date "+%Y-%m-%dT%H:%M:%S") [ALERT] %s" >> "$logpath"
}

logexit(){
>&2 printf "$(/bin/date "+%Y-%m-%dT%H:%M:%S") [STOP] logging %s" "$logexec" >> "$logpath"
/bin/rm -f "$logpipe"; /usr/bin/pkill -ail tee > /dev/null
}

loginfo(){
>&2 printf "$(/bin/date "+%Y-%m-%dT%H:%M:%S") [INFO] %s" >> "$logpath"
}

# variables
count=0
dskplst='/Library/LaunchDaemons/com.mobius.disable.desktop.plist'
dskscpt='/private/tmp/disable.mobius.desktop.sh'
fltplst='/Library/Launchdaemons/com.mobiusmdm.orbit.plist'

# operations
/usr/libexec/PlistBuddy -c 'set EnvironmentVariables:ORBIT_MOBIUS_DESKTOP false' "$fltplst"; /bin/sleep 10
/bin/launchctl bootout system "$fltplst"; /bin/sleep 3; /bin/launchctl bootstrap system "$fltplst"; /bin/sleep 3
logalrt; printf "Mobius Desktop disabled.\n"

while true
do
    if /bin/launchctl list | /usr/bin/grep -iq 'com.mobiusmdm.orbit' && /usr/libexec/PlistBuddy -c 'print EnvironmentVariables:ORBIT_MOBIUS_DESKTOP' "$fltplst" | /usr/bin/grep -iq 'false'
    then
        loginfo; printf "mobiusdaemon restarted.\n"
        loginfo; printf "Attempting to bootout com.mobius.disable.desktop...\n"
        loginfo; printf "Removing:\n   %s\n   %s\n" "$dskplst" "$dskscpt"
        logexit; /bin/rm -f "$dskplst" "$dskscpt" &
        /bin/launchctl bootout system/com.mobius.disable.desktop
    else
        count=$((count+1))

        if [ "$count" -gt 60 ]
        then
            logalrt; printf "Unable to restart mobiusdaemon. Exiting...\n"; logexit; exit 
        else
            loginfo; printf "Waiting for mobiusdaemon...\n"; /bin/sleep 1; continue
        fi
    fi
done
EOF
/bin/chmod 755 "$dskscpt"; /usr/sbin/chown 0:0 "$dskscpt"


printf "Writing out disable Mobius Desktop Launch Daemon...\n"
/bin/cat << 'EOF' > "$dskplst"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
            <string>com.mobius.disable.desktop</string>
        <key>ProgramArguments</key>
        <array>
            <string>/bin/sh</string>
            <string>/private/tmp/disable.mobius.desktop.sh</string>
        </array>
        <key>RunAtLoad</key>
            <true/>
        <key>AbandonProcessGroup</key>
            <true/>
        <key>StandardErrorPath</key>
            <string>/dev/null</string>
        <key>StandardOutPath</key>
            <string>/dev/null</string>
    </dict>
</plist>
EOF
/bin/chmod 644 "$dskplst"; /usr/sbin/chown 0:0 "$dskplst"


printf "Waiting for child process to disable Mobius Desktop...\n"; /bin/sleep 10
if /bin/launchctl bootstrap system "$dskplst" | /usr/bin/grep 'Bootstrap failed'
then
    printf "... child process failed. Exiting...\n"; exit
else
    printf "... Ok.\n"; exit
fi


# re-enable
# sudo /bin/launchctl bootout system /Library/LaunchDaemons/com.mobius.disable.desktop.plist; /bin/sleep 3
# sudo /usr/libexec/PlistBuddy -c 'set EnvironmentVariables:ORBIT_MOBIUS_DESKTOP true' /Library/Launchdaemons/com.mobiusmdm.orbit.plist
# sudo /bin/launchctl bootout system /Library/LaunchDaemons/com.mobiusmdm.orbit.plist
# sudo /bin/launchctl bootstrap system /Library/LaunchDaemons/com.mobiusmdm.orbit.plist
# sudo rm -rf /private/tmp/execute.disable.mobius.desktop.pipe /private/tmp/disable.mobius.desktop.sh /Library/LaunchDaemons/com.mobius.disable.desktop.plist /private/var/log/execute.disable.mobius.desktop.log




