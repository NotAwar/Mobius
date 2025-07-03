module.exports = {


  friendlyName: 'Create android enterprise',


  description: 'Creates a new Android enterprise from a request from a Mobius instance.',


  inputs: {
    signupUrlName: {
      type: 'string',
      required: true,
    },
    enterpriseToken: {
      type: 'string',
      required: true,
    },
    mobiusLicenseKey: {
      type: 'string',
    },
    pubsubPushUrl: {
      type: 'string',
      required: true,
    },
    enterprise: {
      type: {},
      required: true,
      moreInfoUrl: ''
    }
  },


  exits: {
    success: { description: 'An android enterprise was successfully created' },
    enterpriseAlreadyExists: { description: 'An android enterprise already exists for this Mobius instance.', statusCode: 409 },
  },


  fn: async function ({signupUrlName, enterpriseToken, mobiusLicenseKey, pubsubPushUrl, enterprise}) {

    // Parse the Mobius server url from the origin header.
    let mobiusServerUrl = this.req.get('Origin');
    if(!mobiusServerUrl){
      return this.res.badRequest();
    }
    // Check the database for a record of this enterprise.
    let connectionforThisInstanceExists = await AndroidEnterprise.findOne({mobiusServerUrl: mobiusServerUrl});
    // If this request came from a Mobius instance that already has an enterprise set up, return an error.
    if(connectionforThisInstanceExists) {
      throw 'enterpriseAlreadyExists';
    }
    // Generate a uuid to use for the pubsub topic name for this Android enterprise.
    let newPubSubTopicName = 'a' + sails.helpers.strings.uuid();// Google requires that topic names start with a letter, so we'll preprend an 'a' to the generated uuid.
    // Build the full pubsub topic name.
    let fullPubSubTopicName = `projects/${sails.config.custom.androidEnterpriseProjectId}/topics/${newPubSubTopicName}`;
    enterprise.pubsubTopic = fullPubSubTopicName;
    let newSubscriptionName = `projects/${sails.config.custom.androidEnterpriseProjectId}/subscriptions/${newPubSubTopicName}`;

    // Complete the setup of the new Android enterprise.
    // Note: We're using sails.helpers.flow.build here to handle any errors that occurr using google's node library.
    let newEnterprise = await sails.helpers.flow.build(async ()=>{
      let { google } = require('googleapis');
      let androidmanagement = google.androidmanagement('v1');
      let googleAuth = new google.auth.GoogleAuth({
        scopes: [
          'https://www.googleapis.com/auth/androidmanagement',
          'https://www.googleapis.com/auth/pubsub'
        ],
        credentials: {
          client_email: sails.config.custom.androidEnterpriseServiceAccountEmailAddress,// eslint-disable-line camelcase
          private_key: sails.config.custom.androidEnterpriseServiceAccountPrivateKey,// eslint-disable-line camelcase
        },
      });
      // Acquire the google auth client, and bind it to all future calls
      let authClient = await googleAuth.getClient();
      google.options({auth: authClient});
      let pubsub = google.pubsub({version: 'v1'});

      // Create a new pubsub topic for this enterprise.
      // [?]: https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.topics/create
      await pubsub.projects.topics.create({
        name: fullPubSubTopicName,
        requestBody: {
          messageRetentionDuration: '86400s'// 24 hours
        }
      });

      // [?]: https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.topics/getIamPolicy
      // Retrieve the IAM policy for the created pubsub topic.
      let getIamPolicyResponse = await pubsub.projects.topics.getIamPolicy({
        resource: fullPubSubTopicName,
      });
      let newPubSubTopicIamPolicy = getIamPolicyResponse.data;

      // Grand Android device policy the right to publish
      // See: https://developers.google.com/android/management/notifications
      // Default the policy bindings to an empty array if it is not set.
      newPubSubTopicIamPolicy.bindings = newPubSubTopicIamPolicy.bindings || [];
      // Add the Mobius android MDM service account to the policy bindings.
      newPubSubTopicIamPolicy.bindings.push({
        role: 'roles/pubsub.publisher',
        members: ['serviceAccount:android-cloud-policy@system.gserviceaccount.com']
      });

      // Update the pubsub topic's IAM policy
      // [?]: https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.topics/setIamPolicy
      await pubsub.projects.topics.setIamPolicy({
        resource: fullPubSubTopicName,
        requestBody: {
          policy: newPubSubTopicIamPolicy
        }
      });

      // Create a new subscription for the created pubsub topic.
      // [?]: https://cloud.google.com/pubsub/docs/reference/rest/v1/projects.subscriptions/create
      await pubsub.projects.subscriptions.create({
        name: newSubscriptionName,
        requestBody: {
          topic: fullPubSubTopicName,
          ackDeadlineSeconds: 60,
          messageRetentionDuration: '86400s',// 24 hours
          expirationPolicy: {}, // never expire, so that customers can enable Android but actually enroll devices months later
          pushConfig: {
            pushEndpoint: pubsubPushUrl// Use the pubsubPushUrl provided by the Mobius server.
          }
        }
      });

      // Now create the new enterprise for this Mobius server.
      // [?]: https://googleapis.dev/nodejs/googleapis/latest/androidmanagement/classes/Resource$Enterprises.html#create
      let createEnterpriseResponse = await androidmanagement.enterprises.create({
        agreementAccepted: true,
        enterpriseToken: enterpriseToken,
        projectId: sails.config.custom.androidEnterpriseProjectId,
        signupUrlName: signupUrlName,
        requestBody: enterprise,
      });
      return createEnterpriseResponse.data;
    }).intercept((err)=>{
      return new Error(`When attempting to create a new Android enterprise, an error occurred. Error: ${require('util').inspect(err)}`);
    });


    let newAndroidEnterpriseId = newEnterprise.name;
    // Create a new mobiusServerSecret for this Mobius server. This will be included in the response body and will be required in all subsequent requests to Android proxy endpoints.
    let newMobiusServerSecret = await sails.helpers.strings.random.with({len: 30});
    // Update the database record to include details about the created enterprise.
    await AndroidEnterprise.create({
      mobiusServerUrl: mobiusServerUrl,
      mobiusLicenseKey: mobiusLicenseKey,
      androidEnterpriseId: newAndroidEnterpriseId.replace(/enterprises\//, ''),// Remove the /enterprises prefix from the androidEnterpriseId that we save in the website database.
      pubsubTopicName: fullPubSubTopicName,
      pubsubSubscriptionName: newSubscriptionName,
      mobiusServerSecret: newMobiusServerSecret,
    });



    return {
      name: newAndroidEnterpriseId,
      mobiusServerSecret: newMobiusServerSecret,
    };

  }


};
