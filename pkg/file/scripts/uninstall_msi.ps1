$product_code = $PACKAGE_ID

# Mobius uninstalls app using product code that's extracted on upload
msiexec /quiet /x $product_code
Exit $LASTEXITCODE
