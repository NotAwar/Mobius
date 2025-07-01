package_name=$PACKAGE_ID

# Mobius uninstalls app using product name that's extracted on upload
dnf remove --assumeyes "$package_name"
