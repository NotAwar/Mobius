/**
 * Subscription.js
 *
 * @description :: A model definition represents a database table/collection.
 * @docs        :: https://sailsjs.com/docs/concepts/models-and-orm/models
 */

module.exports = {

  attributes: {

    //  ╔═╗╦═╗╦╔╦╗╦╔╦╗╦╦  ╦╔═╗╔═╗
    //  ╠═╝╠╦╝║║║║║ ║ ║╚╗╔╝║╣ ╚═╗
    //  ╩  ╩╚═╩╩ ╩╩ ╩ ╩ ╚╝ ╚═╝╚═╝

    nextBillingAt: {
      type: 'number',
      description: 'A JS Timestamp representing the next billing date for this subscription',
      required: true,
    },

    numberOfHosts: {
      type: 'number',
      description: 'The number of hosts this subscription is valid for',
      required: true,
    },

    subscriptionPrice: {
      type: 'number',
      description: 'The price of this Mobius Premium subscription',
      required: true,
    },

    stripeSubscriptionId: {
      type: 'string',
      description: 'The stripe id for this subscription',
      required: true,
    },

    mobiusLicenseKey: {
      type: 'string',
      example:'1234 1234 1234 1234 1234',
      description: 'The user\'s Mobius Premium license key'
    },

    //  ╔═╗╔╦╗╔╗ ╔═╗╔╦╗╔═╗
    //  ║╣ ║║║╠╩╗║╣  ║║╚═╗
    //  ╚═╝╩ ╩╚═╝╚═╝═╩╝╚═╝


    //  ╔═╗╔═╗╔═╗╔═╗╔═╗╦╔═╗╔╦╗╦╔═╗╔╗╔╔═╗
    //  ╠═╣╚═╗╚═╗║ ║║  ║╠═╣ ║ ║║ ║║║║╚═╗
    //  ╩ ╩╚═╝╚═╝╚═╝╚═╝╩╩ ╩ ╩ ╩╚═╝╝╚╝╚═╝
    user: {
      model: 'User',
      description: 'The user who started this subscription.',
      required: true
    }

  },

};

