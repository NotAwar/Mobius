module.exports = {


  friendlyName: 'View waitlist',


  description: 'Display "Waitlist" page.',


  exits: {

    success: {
      viewTemplatePath: 'pages/try-mobius/waitlist'
    },

    redirect: {
      description: 'This user does not have a valid Mobius Sandbox instance and is being redirected.',
      responseType: 'redirect'
    },


  },


  fn: async function () {
    if(!this.req.me.inSandboxWaitlist){
      throw {redirect: '/try-mobius/sandbox' };
    }
    // Respond with view.
    return {};

  }


};
