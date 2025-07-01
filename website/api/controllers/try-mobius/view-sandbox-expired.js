module.exports = {


  friendlyName: 'View sandbox expired',


  description: 'Display "Sandbox expired" page.',


  exits: {

    success: {
      viewTemplatePath: 'pages/try-mobius/sandbox-expired'
    }

  },


  fn: async function () {

    // Respond with view.
    return {};

  }


};
