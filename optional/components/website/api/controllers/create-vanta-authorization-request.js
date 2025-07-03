module.exports = {


  friendlyName: 'Create Vanta authorization request',


  description: 'Returns a URL used to authorize requests to the user\'s Vanta account from mobiusmdm.com on behalf of the user.',


  inputs: {
    emailAddress: {
      type: 'string',
      required: true,
    },
    mobiusInstanceUrl: {
      type: 'string',
      required: true,
    },
    mobiusApiKey: {
      type: 'string',
      required: true,
    },
    redirectToExternalPageAfterAuthorization: {
      type: 'string',
      description: 'If provided, the user will be sent to this URL after they complete the setup of this integration'
    },
    sharedSecret: {
      type: 'string',
      description: 'A shared secret used to verify external requests to this endpoint.',
      extendedDescription: 'This input is used only when this action runs at the "/api/v1/create-external-vanta-authorization-request" endpoint'
    }
  },


  exits: {
    success: {
      outputType: 'string'
    },
    connectionAlreadyExists: {
      description: 'The Mobius instance url provided is already connected to a Vanta account.',
      statusCode: 409,
    },
    mobiusInstanceNotResponding: {
      description: 'A http request to the user\'s Mobius instance failed.',
      statusCode: 404,
    },
    invalidToken: {
      description: 'The provided token for the api-only user could not be used to authorize requests from mobiusmdm.com',
      statusCode: 403,
    },
    invalidLicense: {
      description: 'The Mobius instance provided is using a Free license.',
      statusCode: 400,
    },
    invalidResponseFromMobiusInstance: {
      description: 'The response body from the Mobius API was invalid.',
      statusCode: 400,
    },
    nonApiOnlyUser: {
      description: 'The provided API token for this Mobius instance is not associated with an api-only user.',
      statusCode: 400,
    },
    insufficientPermissions:{
      description: 'The api-only user associated with the provided token does not have the propper permissions to query the users endpoint.',
      statusCode: 403,
    },
    missingOrInvalidSharedSecret: {
      description: 'The request to set up a Vanta integration has an invalid shared secret',
      statusCode: 401
    }
  },

  fn: async function (inputs) {
    require('assert')(sails.config.custom.sharedSecretForExternalVantaRequests);
    if(this.req.url === '/api/v1/create-external-vanta-authorization-request' && inputs.sharedSecret !== sails.config.custom.sharedSecretForExternalVantaRequests) {
      throw 'missingOrInvalidSharedSecret';
    }

    let url = require('url');

    // Look for any existing VantaConnection records that use this mobius instance URL.
    let existingConnectionRecord = await VantaConnection.findOne({mobiusInstanceUrl: inputs.mobiusInstanceUrl});

    // Generate the `state` string for this request.
    let generatedStateForThisRequest = await sails.helpers.strings.random.with({len: 10});

    // Generate a sourceId for this user. This value will be used as the indentifier of ther user's vanta connection
    let generatedSourceIdSuffix = await sails.helpers.strings.random.with({len: 20, style: 'url-friendly'});
    let sourceIDForThisRequest = 'mobius_'+generatedSourceIdSuffix;

    if(existingConnectionRecord) {
      // If an active Vanta connection exists for the provided Mobius instance url, we'll throw a 'connectionAlreadyExists' exit, and the user will be asked to contact us to make changes to the existing vanta connection.
      if(existingConnectionRecord.isConnectedToVanta) {
        throw 'connectionAlreadyExists';
      } else if(existingConnectionRecord.mobiusApiKey !== inputs.mobiusApiKey && existingConnectionRecord.emailAddress !== inputs.emailAddress) {
      // If an incomplete connection exists, and the API token and email address provided do not match. The user will be asked to contact us to make changes to their connection.
        throw 'connectionAlreadyExists';
      } else {
        // If an inactive and incomplete Vanta connection exists that uses the same API token and email address, we'll use the sourceId from that record for this request.
        sourceIDForThisRequest = existingConnectionRecord.vantaSourceId;
      }
    }


    // Check the mobius instance url and API key provided
    let responseFromMobiusInstance = await sails.helpers.http.get(inputs.mobiusInstanceUrl+'/api/v1/mobius/me',{},{'Authorization': 'Bearer ' +inputs.mobiusApiKey})
    .intercept('requestFailed', 'mobiusInstanceNotResponding')
    .intercept('non200Response', 'invalidToken')
    .intercept((error)=>{
      return new Error(`When sending a request to a Mobius instance's /me endpoint to verify that a token meets the requirements for a Vanta connection, an error occurred: ${error}`);
    });

    // Throw an error if the response from the Mobius instance's /me API endpoint does not contain a user.
    if(!responseFromMobiusInstance.user){
      throw 'invalidResponseFromMobiusInstance';
    }

    // Throw an error if the provided API token is not an API-only user.
    if(!responseFromMobiusInstance.user.api_only) {
      throw 'nonApiOnlyUser';
    }

    // If the API-only user associated with the token provided does not have the admin role, we'll throw an error.
    // We require an admin token so we can send Vanta data about all of the active user accounts on the requesting user's Mobius instance
    if(responseFromMobiusInstance.user.global_role !== 'admin') {
      throw 'insufficientPermissions';
    }

    // Send a request to the provided Mobius instance's /config endpoint to check their license tier.
    let configResponse = await sails.helpers.http.get(inputs.mobiusInstanceUrl+'/api/v1/mobius/config', {}, {'Authorization': 'Bearer ' +inputs.mobiusApiKey})
    .intercept('requestFailed','mobiusInstanceNotResponding')
    .intercept('non200Response', 'invalidToken')
    .intercept((error)=>{
      return new Error(`When sending a request to a Mobius instance's /config API endpoint for a Vanta connection, an error occurred: ${error}`);
    });


    // Throw an error if the response from the Mobius instance's /config API endpoint does not contain a license.
    if(!configResponse.license){
      throw 'invalidResponseFromMobiusInstance';
    }

    // If the user's Mobius instance has a free license, we'll throw the 'invalidLicense' exit and let the user know that this is only available for Mobius Premium subscribers.
    if(configResponse.license.tier === 'free') {
      throw 'invalidLicense';
    }

    // If we're not using an existing vantaConnection record for this request, we'll create a new one.
    if(!existingConnectionRecord) {
      // Create the VantaConnection record for this request.
      await VantaConnection.create({
        emailAddress: inputs.emailAddress,
        vantaSourceId: sourceIDForThisRequest,
        mobiusInstanceUrl: inputs.mobiusInstanceUrl,
        mobiusApiKey: inputs.mobiusApiKey,
      });
    }
    // Build the authorization URL for this request.
    let vantaAuthorizationRequestURL = `https://app.vanta.com/oauth/authorize?client_id=${encodeURIComponent(sails.config.custom.vantaAuthorizationClientId)}&scope=connectors.self:write-resource connectors.self:read-resource&state=${encodeURIComponent(generatedStateForThisRequest)}&source_id=${encodeURIComponent(sourceIDForThisRequest)}&redirect_uri=${encodeURIComponent(url.resolve(sails.config.custom.baseUrl, '/vanta-authorization'))}&response_type=code`;

    if(inputs.redirectToExternalPageAfterAuthorization){
      let internalRedirectUrl =  `${sails.config.custom.baseUrl}/redirect-vanta-authorization-request?vantaSourceId=${encodeURIComponent(sourceIDForThisRequest)}&state=${encodeURIComponent(generatedStateForThisRequest)}&vantaAuthorizationRequestURL=${encodeURIComponent(vantaAuthorizationRequestURL)}&redirectAfterSetup=${encodeURIComponent(inputs.redirectToExternalPageAfterAuthorization)}`;

      return internalRedirectUrl;
      // If the useInternalRedirect input was provided, we'll return the URL of an internal endpoiint that will set the required cookies for this request.
    } else {
      // Otherwise, if this request came from a user on the connect-vanta page, we'll set the cookies are redirect them directly to Vanta.
      // Set a `state` cookie on the user's browser. This value will be checked against a query parameter when the user returns to mobiusmdm.com.
      this.res.cookie('state', generatedStateForThisRequest, {signed: true});
      // Set the sourceId to a cookie, we'll use this value to find the database record we created for this request when the user returns to mobiusmdm.com.
      this.res.cookie('vantaSourceId', sourceIDForThisRequest, {signed: true});
      return vantaAuthorizationRequestURL;
    }
  }


};
