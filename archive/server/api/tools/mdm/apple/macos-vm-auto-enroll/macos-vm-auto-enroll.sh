#!/bin/sh

# Enable job control in shell script
set -m

# Mobius enroll secret placed in $MOBIUS_ENROLL_SECRET
# Mobius URL placed in $MOBIUS_URL
# Optional VM name in $MACOS_ENROLLMENT_VM_NAME
# Optional VM image in $MACOS_ENROLLMENT_VM_IMAGE
#  For others see https://tart.run/quick-start/
#  - ghcr.io/cirruslabs/macos-ventura-base:latest
#  - ghcr.io/cirruslabs/macos-monterey-base:latest

vm_name="${MACOS_ENROLLMENT_VM_NAME:-enrollment-test}"
image_name="${MACOS_ENROLLMENT_VM_IMAGE:-ghcr.io/cirruslabs/macos-sonoma-base:latest}"

alias ssh_cmd="sshpass -p admin ssh -o \"StrictHostKeyChecking no\" admin@\$(tart ip $vm_name)"
alias ssh_interactive_cmd="sshpass -p admin ssh -o \"StrictHostKeyChecking no\" -t admin@\$(tart ip $vm_name)"
alias scp_cmd="sshpass -p admin scp -o \"StrictHostKeyChecking no\""

check_ip() {
    counter=0
    while [ $counter -lt 5 ]; do
        if tart ip "$vm_name" > /dev/null; then
            break
        fi
        sleep 2
        counter=$((counter+1))
    done

    if [ $counter -eq 5 ]; then
        echo "Failed to get IP address"
        exit 1
    fi
}

# Make sure we're in the script directory
cd "$(dirname "$0")"

# cd to the git root
cd "$(git rev-parse --show-toplevel)"


if [ "$MOBIUS_URL" = "" ]; then
    echo "MOBIUS_URL missing"
    exit 1
fi

# Remove the trailing slash if present
MOBIUS_URL=${MOBIUS_URL%/}

if [ "$MOBIUS_ENROLL_SECRET" = "" ]; then
    echo "MOBIUS_ENROLL_SECRET missing"
    exit 1
fi

if ! which tart >/dev/null; then
    echo "install tart VM https://tart.run/"
    exit 1
fi

echo "Deleting old mobius package"
[ -f mobius-osquery.pkg ] && rm mobius-osquery.pkg

echo "Creating mobius package..."
./build/mobiuscli package --type=pkg --enable-scripts --mobius-desktop --disable-open-folder --mobius-url="$MOBIUS_URL" --enroll-secret="$MOBIUS_ENROLL_SECRET"

if [ ! -f mobius-osquery.pkg ]; then
    echo "package not generated"
    exit 1
fi

if tart list | grep $vm_name >/dev/null 2>&1; then
    echo 'Enrollment test VM exists, deleting...'
    tart stop $vm_name
    tart delete $vm_name
fi

echo "Creating new $image_name VM called $vm_name..."
tart clone $image_name $vm_name

echo "Starting VM $vm_name and detatching"
tart run $vm_name &

echo "Waiting for VM to boot"
check_ip

echo "Running uname"
ssh_cmd "uname -a"

echo "Copying package to VM"
scp_cmd mobius-osquery.pkg admin@$(tart ip $vm_name):

echo "Installing mobius in VM"
ssh_cmd "echo admin | sudo -S installer -pkg mobius-osquery.pkg -target /"

echo "Waiting for identifier to appear"
ssh_cmd "while true; do echo 'checking for identifier'; [ -f /opt/orbit/identifier ] && echo 'identifier found' && exit; sleep 5; done"

echo "Waiting for registration to be complete"
ssh_cmd "while true; do echo 'checking server'; curl -f $MOBIUS_URL/device/\$(cat /opt/orbit/identifier) > /dev/null 2>&1; [ \$? -eq 0 ] && exit; sleep 5; done"

echo "Fetching MDM profile"
ssh_cmd "echo $MOBIUS_URL/api/latest/mobius/device/\$(cat /opt/orbit/identifier)/mdm/apple/manual_enrollment_profile"
ssh_cmd "curl -o mdm_profile.mobileconfig $MOBIUS_URL/api/latest/mobius/device/\$(cat /opt/orbit/identifier)/mdm/apple/manual_enrollment_profile"

echo "Opening MDM profile"
ssh_cmd "open mdm_profile.mobileconfig"

ssh_cmd "open ."

sleep 1

echo "Opening profile settings"
ssh_cmd "open x-apple.systempreferences:com.apple.preferences.configurationprofiles"

echo "Complete the MDM certificate enrolment with the GUI"
echo "The default password for user 'admin' is 'admin'"

echo "Opening shell"
ssh_interactive_cmd "zsh"

echo "Reattaching to VM process"
fg
