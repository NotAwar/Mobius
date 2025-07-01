# Using `toggle-mdm-dev` to enable and disable MDM (Mobile Device Management) / ABM (Apple Business Manager) for development

1. Set up all of the necessary credentials for using MDM and ABM as outlined in the [MDM setup and
   testing
   docs](https://mobiusmdm.com/docs/contributing/testing-and-local-development#mdm-setup-and-testing).
   Take note of the path where you've stored these credentials.

2. Make a mobius env file containing the following or similar logic, including the above path where specified:

  ```
    if [[ $USE_MDM == "1" ]]; then

    # MDM Feature Flag:

    MDM_PATH="{Replace this string, including braces, with the path to your credentials}"

    # Apple Push Certificates
    export MOBIUS_MDM_APPLE_SCEP_CHALLENGE=scepchallenge
    export MOBIUS_MDM_APPLE_SCEP_CERT=$MDM_PATH"mobius-mdm-apple-scep.crt"
    export MOBIUS_MDM_APPLE_SCEP_KEY=$MDM_PATH"mobius-mdm-apple-scep.key"

    # Apple Push Notification Service (APNS) credentials
    export MOBIUS_MDM_APPLE_APNS_CERT=$MDM_PATH"mdmcert.download.push.pem"
    export MOBIUS_MDM_APPLE_APNS_KEY=$MDM_PATH"mdmcert.download.push.key"

    # Apple Business Manager (ABM) credentials
    export MOBIUS_MDM_APPLE_BM_SERVER_TOKEN=$MDM_PATH"downloadtoken.p7m"
    export MOBIUS_MDM_APPLE_BM_CERT=$MDM_PATH"mobius-apple-mdm-bm-public-key.crt"
    export MOBIUS_MDM_APPLE_BM_KEY=$MDM_PATH"mobius-apple-mdm-bm-private.key"

    else

    unset MOBIUS_MDM_APPLE_SCEP_CHALLENGE
    unset MOBIUS_MDM_APPLE_SCEP_CERT
    unset MOBIUS_MDM_APPLE_SCEP_KEY
    unset MOBIUS_MDM_APPLE_BM_SERVER_TOKEN
    unset MOBIUS_MDM_APPLE_BM_CERT
    unset MOBIUS_MDM_APPLE_BM_KEY
    #below files are from the shared Mobius 1Password
    unset MOBIUS_MDM_APPLE_APNS_CERT
    unset MOBIUS_MDM_APPLE_APNS_KEY
    fi
  ```

3. If you haven't already, add an environment variable called `MOBIUS_ENV_PATH` to your shell config
   file. Source it or open a new shell.
4. Add the directory containing `toggle-mdm-dev`, likely this one, to your $PATH. If you did that by
   adding it to your shell config, source it or open a new shell.
5. To toggle MDM and ABM, execute `source toggle-mdm-dev`
6. To enable MDM without ABM set up, comment out the variables in your env file pointing to the
   various credentials (like below), then `source toggle-mdm-dev` *twice*, to toggle off then back on again, the
   MDM feature flag.
  
  ```
  if [[ $USE_MDM == "1" ]]; then

  # MDM_PATH="/Users/jacob/.envs/mobius_env/mdm/"

  # # Apple Push Certificates
  # export MOBIUS_MDM_APPLE_SCEP_CHALLENGE=scepchallenge
  # export MOBIUS_MDM_APPLE_SCEP_CERT=$MDM_PATH"mobius-mdm-apple-scep.crt"
  # export MOBIUS_MDM_APPLE_SCEP_KEY=$MDM_PATH"mobius-mdm-apple-scep.key"

  # # APNS credentials from Mobius shared 1Password
  # export MOBIUS_MDM_APPLE_APNS_CERT=$MDM_PATH"mdmcert.download.push.pem"
  # export MOBIUS_MDM_APPLE_APNS_KEY=$MDM_PATH"mdmcert.download.push.key"

  # # Apple Business Manager
  # export MOBIUS_MDM_APPLE_BM_SERVER_TOKEN=$MDM_PATH"downloadtoken.p7m"
  # export MOBIUS_MDM_APPLE_BM_CERT=$MDM_PATH"mobius-apple-mdm-bm-public-key.crt"
  # export MOBIUS_MDM_APPLE_BM_KEY=$MDM_PATH"mobius-apple-mdm-bm-private.key"
  ```
