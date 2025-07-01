module.exports = {


  friendlyName: 'Provision Sandbox instance for one user and deliver email.',


  description: 'Provisions a new Mobius Sandbox instance for a user on the Mobius Sandbox waitlist, and sends an email to the user.',

  extendedDescription: 'This script will provision a Sandbox instance for the user who has been on the waitlist the longest.',


  fn: async function () {


    let earliestCreatedUserCurrentlyOnWaitlist = await User.find({inSandboxWaitlist: true})
    .limit(1)
    .sort('createdAt ASC');

    // If there are no users on the Mobius sandbox waitlist, end the script.
    if(earliestCreatedUserCurrentlyOnWaitlist.length === 0){
      sails.log('There are no users currently waiting on the Mobius Sandbox Waitlist.');
      return;
    }

    let userToRemoveFromSandboxWaitlist = earliestCreatedUserCurrentlyOnWaitlist[0];

    let sandboxInstanceDetails = await sails.helpers.mobiusSandboxCloudProvisioner.provisionNewMobiusSandboxInstance.with({
      firstName: userToRemoveFromSandboxWaitlist.firstName,
      lastName: userToRemoveFromSandboxWaitlist.lastName,
      emailAddress: userToRemoveFromSandboxWaitlist.emailAddress,
    })
    .intercept((err)=>{
      return new Error(`When attempting to provision a new Mobius Sandbox instance for a User (id:${userToRemoveFromSandboxWaitlist.id}), an error occured. Full error: ${err}`);
    });


    await User.updateOne({id: userToRemoveFromSandboxWaitlist.id})
    .set({
      mobiusSandboxURL: sandboxInstanceDetails.mobiusSandboxURL,
      mobiusSandboxExpiresAt: sandboxInstanceDetails.mobiusSandboxExpiresAt,
      mobiusSandboxDemoKey: sandboxInstanceDetails.mobiusSandboxDemoKey,
      inSandboxWaitlist: false,
    });


    // Send the user an email to let them know that their Mobius sandbox instance is ready.
    await sails.helpers.sendTemplateEmail.with({
      to: userToRemoveFromSandboxWaitlist.emailAddress,
      from: sails.config.custom.fromEmailAddress,
      fromName: sails.config.custom.fromName,
      subject: 'Your Mobius Sandbox instance is ready!',
      template: 'email-sandbox-ready-approved',
      templateData: {},
    });

    sails.log(`Successfully removed a user (id: ${userToRemoveFromSandboxWaitlist.id}) from the Mobius Sandbox waitlist.`);

  }


};

