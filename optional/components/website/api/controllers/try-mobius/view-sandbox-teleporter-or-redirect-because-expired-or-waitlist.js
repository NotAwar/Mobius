module.exports = {


  friendlyName: 'View sandbox teleporter or redirect because sandbox expired or waitlist',

  description:
    `Display "Sandbox teleporter" page (an auto-submitting interstitial HTML form used as a hack to grab a bit of HTML
    from the Mobius Sandbox instance, which sets browser localstorage to consider this user logged in and "teleports" them,
    magically authenticated, into their Mobius Sandbox instance running on a different domain), or redirect the user to a
    page about their sandbox instance being expired, or a page explaining that they are on the Mobius Sandbox waitlist.`,

  moreInfoUrl: 'https://github.com/notawar/mobius/pull/6380',


  exits: {

    success: {
      viewTemplatePath: 'pages/try-mobius/sandbox-teleporter',
      description: 'This user is being logged into their Mobius Sandbox instance.'
    },

    redirect: {
      description: 'This user does not have a valid Mobius Sandbox instance and is being redirected.',
      responseType: 'redirect'
    },

  },


  fn: async function () {
    // FUTURE: Remove the route for this controller when all active sandbox instances have expired.

    if(!this.req.me) {
      throw {redirect: '/try-mobius/login' };
    }

    // If the user does not have a Mobius sandbox instance, redirect them to the /mobiuscli-preview page.
    if(!this.req.me.mobiusSandboxURL || !this.req.me.mobiusSandboxExpiresAt || !this.req.me.mobiusSandboxDemoKey) {
      throw {redirect: '/try-mobius/mobiuscli-preview' };
    }

    // Redirect users with expired sandbox instances to the /mobiuscli-preview page.
    if(this.req.me.mobiusSandboxExpiresAt < Date.now()){
      throw {redirect: '/try-mobius/mobiuscli-preview' };
    }
    // IWMIH, the user has an unexpired Mobius sandbox instance, and will be taken to to the sandbox teleporter page.
    return {
      hideHeaderOnThisPage: true,
    };

  }


};
