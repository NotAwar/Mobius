package_name=$PACKAGE_ID

# Mobius uninstalls app using product name that's extracted on upload
apt-get remove --purge --assume-yes "$package_name"
