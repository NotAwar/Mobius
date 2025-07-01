# Please don't delete. This script is referenced in the guide here: https://mobiusmdm.com/guides/enforce-disk-encryption

$Username = "IT admin"
$Password = ConvertTo-SecureString "StrongPassword123!" -AsPlainText -Force

# Create the local user account
New-LocalUser -Name $Username -Password $Password -FullName "Mobius IT admin" 
-Description "Admin account used to login when the end user forgets their 
password or the host is returned to Mobius." 
-AccountNeverExpires

# Add the user to the Administrators group
Add-LocalGroupMember -Group "Administrators" -Member $Username