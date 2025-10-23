#!/bin/sh
# Please don't delete. This script is referenced in the guide here: https://mobiusmdm.com/guides/how-to-uninstall-mobiusdaemon

if [ $(id -u) -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

function remove_mobius {
    set -x
    rm -rf /Library/LaunchDaemons/com.mobiusmdm.orbit.plist /var/lib/orbit /usr/local/bin/orbit /var/log/orbit /opt/orbit/
    pkgutil --forget com.mobiusmdm.orbit.base.pkg || true
    launchctl stop com.mobiusmdm.orbit
    launchctl unload /Library/LaunchDaemons/com.mobiusmdm.orbit.plist
    pkill mobius-desktop || true
    
    # Check MDM status on a macOS device
    mdm_status=$(profiles status -type enrollment)
    
    # Check for MDM enrollment status and cleanup enrollment profile
    if echo "$mdm_status" | grep -q "MDM enrollment: Yes"; then
        echo "This Mac is MDM enrolled. Removing enrollment profile."
        profiles remove -identifier com.mobiusmdm.mobius.mdm.apple
    elif echo "$mdm_status" | grep -q "MDM enrollment: No"; then
        echo "This Mac is not MDM enrolled."
    else
        echo "MDM status is unknown."
    fi
}

if [ "$1" = "remove" ]; then
    # We are in the detached child process
    # Give the parent process time to report the success before removing
    echo "inside remove process" >>/tmp/mobius_remove_log.txt
    sleep 15
    
    # We are root
    remove_mobius >>/tmp/mobius_remove_log.txt 2>&1
else
    # We are in the parent shell, start the detached child and return success
    echo "Removing mobiusdaemon, system will be unenrolled in 15 seconds..."
    echo "Executing detached child process"
    
    # We are root
    bash -c "bash $0 remove >/dev/null 2>/dev/null </dev/null &"
fi
