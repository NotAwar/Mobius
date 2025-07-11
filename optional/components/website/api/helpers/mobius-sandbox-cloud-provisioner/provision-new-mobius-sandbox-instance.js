module.exports = {


  friendlyName: 'Provision new Mobius Sandbox instance',


  description: 'Provisions a new Mobius Sandbox instance and returns the details of the Sandbox instance.',


  inputs: {

    firstName: {
      type: 'string',
      required: true,
      description: 'The first name of the user who is having a Mobius Sandbox instance provisioned for them.',
      extendedDescription: 'This will be used in the Mobius instance'
    },
    lastName: {
      type: 'string',
      required: true,
      description: 'The last name of the user who is having a Mobius Sandbox instance provisioned for them.',
      extendedDescription: 'This will be used in the Mobius instance'
    },
    emailAddress: {
      type: 'string',
      required: true,
      description: 'The email address of the User record that is having a Mobius sandbox instance provisioned for them.',
      extendedDescription: 'This will be used in the Mobius instance'
    },

  },


  exits: {

    success: {
      description: 'All done.',
      outputFriendlyName: 'Sandbox instance details',
      outputType: {
        mobiusSandboxDemoKey: 'string',
        mobiusSandboxExpiresAt: 'number',
        mobiusSandboxURL: 'string',
      },
    },

    requestToProvisionerTimedOut: {
      description: 'The request to the Mobius Sandbox provisioner exceeded the set timeout.',
    },
  },


  fn: async function ({firstName, lastName, emailAddress}) {

    const FIVE_DAYS_IN_MS = (5*24*60*60*1000);
    // Creating an expiration JS timestamp for the Mobius sandbox instance. NOTE: We send this value to the cloud provisioner API as an ISO 8601 string.
    let mobiusSandboxExpiresAt = Date.now() + FIVE_DAYS_IN_MS;

    // Creating a mobiusSandboxDemoKey, this will be used for the user's password when we log them into their Sandbox instance.
    let mobiusSandboxDemoKey = await sails.helpers.strings.uuid();

    // Send a POST request to the cloud provisioner API
    let cloudProvisionerResponseData = await sails.helpers.http.post.with({
      url: 'https://sandbox.mobiusmdm.com/new',
      data: {
        'name': firstName + ' ' + lastName,
        'email': emailAddress,
        'password': mobiusSandboxDemoKey, //« this provisioner API was originally designed to accept passwords, but rather than specifying the real plaintext password, since users always access Mobius Sandbox from their mobiusmdm.com account anyway, this generated demo key is used instead to avoid any confusion
        'sandbox_expiration': new Date(mobiusSandboxExpiresAt).toISOString(), // sending expiration_timestamp as an ISO string.
      },
      headers: {
        'Authorization':sails.config.custom.cloudProvisionerSecret
      }
    })
    .timeout(10000)
    .intercept(['requestFailed', 'non200Response'], (err)=>{
      // If we received a non-200 response from the cloud provisioner API, we'll throw a 500 error.
      return new Error('When attempting to provision a Sandbox instance for a user on the Mobius Sandbox waitlist ('+emailAddress+'), the cloud provisioner gave a non 200 response. Raw response received from provisioner: '+err.stack);
    })
    .intercept({name: 'TimeoutError'},()=>{
      // If the request timed out, log a warning and return a 'requestToSandboxTimedOut' response.
      return 'requestToProvisionerTimedOut';
    });

    if(!cloudProvisionerResponseData.URL) {
      // If we didn't receive a URL in the response from the cloud provisioner API, we'll throw an error before we save the new user record and the user will need to try to sign up again.
      throw new Error(
        `The response data from the cloud provisioner API was malformed. It did not contain a valid Mobius Sandbox instance URL in its expected "URL" property.
        Here is the malformed response data (parsed response body) from the cloud provisioner API: ${cloudProvisionerResponseData}`
      );
    }

    // Start polling the /healthz endpoint of the created Mobius Sandbox instance, once it returns a 200 response, we'll continue.
    await sails.helpers.flow.until( async()=>{
      let healthCheckResponse = await sails.helpers.http.sendHttpRequest('GET', cloudProvisionerResponseData.URL+'/healthz')
      .timeout(5000)
      .tolerate('non200Response')
      .tolerate('requestFailed')
      .tolerate({name: 'TimeoutError'});
      if(healthCheckResponse) {
        return true;
      }
    }, 10000)//∞
    .intercept('tookTooLong', ()=>{
      return new Error('This newly provisioned Mobius Sandbox instance (for '+emailAddress+') is taking too long to respond with a 2xx status code, even after repeatedly polling the health check endpoint.  Note that failed requests and non-2xx responses from the health check endpoint were ignored during polling.  Search for a bit of non-dynamic text from this error message in the mobiusmdm.com source code for more info on exactly how this polling works.');
    });

    return {
      mobiusSandboxDemoKey,
      mobiusSandboxExpiresAt,
      mobiusSandboxURL: cloudProvisionerResponseData.URL,
    };

  }


};

