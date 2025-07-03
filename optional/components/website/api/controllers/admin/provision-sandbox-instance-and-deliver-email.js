module.exports = {


  friendlyName: 'Provision sandbox instance and deliver email',


  description: 'Provisions a Mobius sandbox for a user and delivers an email to a user letting them know their Mobius Sandbox instance is ready.',


  inputs: {
    userId: {
      type: 'number',
      description: 'The database ID of the user who is currently on the Mobius Sandbox waitlist',
      required: true
    }
  },


  exits: {
    success: {
      description: 'A user was successfully removed from the Mobius Sandbox waitlist.'
    },
  },


  fn: async function ({userId}) {

    let userToRemoveFromSandboxWaitlist = await User.findOne({id: userId});

    if(!userToRemoveFromSandboxWaitlist.inSandboxWaitlist) {
      throw new Error(`When attempting to provision a Mobius Sandbox instance for a user (id:${userId}) who is on the waitlist, the user record associated with the provided ID has already been removed from the waitlist.`);
    }

    let sandboxInstanceDetails = await sails.helpers.mobiusSandboxCloudProvisioner.provisionNewMobiusSandboxInstance.with({
      firstName: userToRemoveFromSandboxWaitlist.firstName,
      lastName: userToRemoveFromSandboxWaitlist.lastName,
      emailAddress: userToRemoveFromSandboxWaitlist.emailAddress,
    })
    .intercept((err)=>{
      return new Error(`When attempting to provision a new Mobius Sandbox instance for a User (id:${userToRemoveFromSandboxWaitlist.id}), an error occurred. Full error: ${err}`);
    });

    await User.updateOne({id: userId}).set({
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

    // All done.
    return;

  }


};
