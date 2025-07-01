parasails.registerPage('start', {
  //  ╦╔╗╔╦╔╦╗╦╔═╗╦    ╔═╗╔╦╗╔═╗╔╦╗╔═╗
  //  ║║║║║ ║ ║╠═╣║    ╚═╗ ║ ╠═╣ ║ ║╣
  //  ╩╝╚╝╩ ╩ ╩╩ ╩╩═╝  ╚═╝ ╩ ╩ ╩ ╩ ╚═╝
  data: {
    currentStep: 'start',

    syncing: false,

    // Form data
    formData: {
      'start': {stepCompleted: true},
      'what-are-you-using-mobius-for': {},
      'have-you-ever-used-mobius': {},
      'how-many-hosts': {},
      'will-you-be-self-hosting': {},
      'what-are-you-working-on-eo-security': {},
      'what-does-your-team-manage-eo-it': {},
      'what-does-your-team-manage-vm': {},
      'what-do-you-manage-mdm': {},
      'message-about-cross-platform-mdm': {stepCompleted: true},
      'is-it-any-good': {stepCompleted: true},
      'what-did-you-think': {},
      'deploy-mobius-in-your-environment': {stepCompleted: true},
      'thanks-for-checking-out-mobius': {stepCompleted: true},
      'how-was-your-deployment': {},
      'whats-left-to-get-you-set-up': {},
    },

    psychologicalStage: '2 - Aware',
    // For tracking client-side validation errors in our form.
    // > Has property set to `true` for each invalid property in `formData`.
    formErrors: { /* … */ },

    formRules: {},
    primaryBuyingSituationFormRules: {
      primaryBuyingSituation: {required: true}
    },
    isUsingMobiusFormRules: {
      mobiusUseStatus: {required: true}
    },
    numberOfHostsFormRules: {
      numberOfHosts: {required: true}
    },
    hostingMobiusFormRules: {
      willSelfHost: {required: true}
    },
    endpointOpsSecurityWorkingOnFormRules: {
      endpointOpsSecurityUseCase: {required: true}
    },
    endpointOpsItUseCaseFormRules: {
      endpointOpsItUseCase: {required: true}
    },
    vmUseCaseFormRules: {
      vmUseCase: {required: true}
    },
    mdmUseCaseFormRules: {
      mdmUseCase: {required: true}
    },
    endpointOpsSecurityIsItAnyGoodFormRules: {
      isItAnyGood: {required: true}
    },
    endpointOpsSecurityWhatDidYouThinkFormRules: {
      whatDidYouThink: {required: true}
    },
    howWasYourDeploymentFormRules: {
      howWasYourDeployment: {required: true}
    },
    whatsLeftToGetYouSetUpFormRules: {
      whatsLeftToGetSetUp: {required: true}
    },
    previouslyAnsweredQuestions: {},

    // Server error state for the forms
    cloudError: '',

    // Success state when form has been submitted
    cloudSuccess: false,
    primaryBuyingSituation: undefined,
  },

  //  ╦  ╦╔═╗╔═╗╔═╗╦ ╦╔═╗╦  ╔═╗
  //  ║  ║╠╣ ║╣ ║  ╚╦╝║  ║  ║╣
  //  ╩═╝╩╚  ╚═╝╚═╝ ╩ ╚═╝╩═╝╚═╝
  beforeMount: function() {
    //…
    if(this.currentStep !== 'start'){
      this.prefillPreviousAnswers();
    }
    // If this user has not completed the 'what are you using mobius for' step, and has a primaryBuyingSituation set by an ad. prefill the formData for this step.
    if(this.primaryBuyingSituation && _.isEmpty(this.formData['what-are-you-using-mobius-for'])){
      if(this.primaryBuyingSituation !== 'vm') {
        this.formData['what-are-you-using-mobius-for'] = {primaryBuyingSituation: this.primaryBuyingSituation};
      }
    }
    if(this.me.psychologicalStage){
      this.psychologicalStage = this.me.psychologicalStage;
    }
    if(window.location.hash) {
      if(window.analytics !== undefined) {
        if(window.location.hash === '#signup') {
          analytics.identify(this.me.id, {
            email: this.me.emailAddress,
            firstName: this.me.firstName,
            lastName: this.me.lastName,
            company: this.me.organization,
            primaryBuyingSituation: this.me.primaryBuyingSituation,
            psychologicalStage: this.me.psychologicalStage,
          });
          analytics.track('mobius_website__sign_up');
        } else if(window.location.hash === '#login') {
          analytics.identify(this.me.id, {
            email: this.me.emailAddress,
            firstName: this.me.firstName,
            lastName: this.me.lastName,
            company: this.me.organization,
            primaryBuyingSituation: this.me.primaryBuyingSituation,
            psychologicalStage: this.me.psychologicalStage,
          });
        }
      }
      window.location.hash = '';
    }
  },
  mounted: async function() {
    //…
  },

  //  ╦╔╗╔╔╦╗╔═╗╦═╗╔═╗╔═╗╔╦╗╦╔═╗╔╗╔╔═╗
  //  ║║║║ ║ ║╣ ╠╦╝╠═╣║   ║ ║║ ║║║║╚═╗
  //  ╩╝╚╝ ╩ ╚═╝╩╚═╩ ╩╚═╝ ╩ ╩╚═╝╝╚╝╚═╝
  methods: {
    handleSubmittingForm: async function(argins) {
      let formDataForThisStep = _.clone(argins);
      let nextStep = this.getNextStep();
      let questionanireProgress = await Cloud.saveQuestionnaireProgress.with({
        currentStep: this.currentStep,
        formData: formDataForThisStep,
      });

      this.previouslyAnsweredQuestions[this.currentStep] = questionanireProgress.getStartedProgress[this.currentStep];
      this.psychologicalStage = questionanireProgress.psychologicalStage;
      this.primaryBuyingSituation = questionanireProgress.primaryBuyingSituation;
      if(typeof analytics !== 'undefined') {
        analytics.identify(this.me.id, {
          email: this.me.emailAddress,
          firstName: this.me.firstName,
          lastName: this.me.lastName,
          company: this.me.organization,
          primaryBuyingSituation: this.primaryBuyingSituation,
          psychologicalStage: this.psychologicalStage,
        });
      }
      if(_.startsWith(nextStep, '/')){
        this.goto(nextStep);
      } else {
        this.syncing = false;
        this.currentStep = nextStep;
      }
    },
    clickGoToPreviousStep: async function() {
      switch(this.currentStep) {
        case 'what-are-you-using-mobius-for':
          this.currentStep = 'start';
          break;
        case 'have-you-ever-used-mobius':
          this.currentStep = 'what-are-you-using-mobius-for';
          break;
        case 'how-many-hosts':
          if(this.formData['have-you-ever-used-mobius'].mobiusUseStatus === 'yes-recently-deployed' || this.formData['have-you-ever-used-mobius'].mobiusUseStatus === 'yes-deployed') {
            this.currentStep = 'have-you-ever-used-mobius';
          } else {
            this.currentStep = 'what-did-you-think';
          }
          break;
        case 'will-you-be-self-hosting':
          this.currentStep = 'how-many-hosts';
          break;
        case 'self-hosted-deploy':
          this.currentStep = 'will-you-be-self-hosting';
          break;
        case 'managed-cloud-for-growing-deployments':
          if(this.formData['have-you-ever-used-mobius'].mobiusUseStatus === 'yes-recently-deployed' || this.formData['have-you-ever-used-mobius'].mobiusUseStatus === 'yes-deployed') {
            this.currentStep = 'will-you-be-self-hosting';
          } else {
            this.currentStep = 'how-many-hosts';
          }
          break;
        case 'what-are-you-working-on-eo-security':
          this.currentStep = 'have-you-ever-used-mobius';
          break;
        case 'is-it-any-good':
          let primaryBuyingSituation = this.formData['what-are-you-using-mobius-for'].primaryBuyingSituation;
          if(primaryBuyingSituation === 'eo-security'){
            this.currentStep = 'what-are-you-working-on-eo-security';
          } else if(primaryBuyingSituation === 'eo-it') {
            this.currentStep = 'what-does-your-team-manage-eo-it';
          } else if(primaryBuyingSituation === 'vm') {
            this.currentStep = 'what-does-your-team-manage-vm';
          } else if(primaryBuyingSituation === 'mdm') {
            this.currentStep = 'message-about-cross-platform-mdm';
          }
          break;
        case 'message-about-cross-platform-mdm':
          this.currentStep = 'what-do-you-manage-mdm';
          break;
        case 'lets-talk-to-your-team':
          this.currentStep = 'how-many-hosts';
          break;
        case 'welcome-to-mobius':
          this.currentStep = 'have-you-ever-used-mobius';
          break;
        case 'deploy-mobius-in-your-environment':
          this.currentStep = 'what-did-you-think';
          break;
        case 'what-did-you-think':
          this.currentStep = 'is-it-any-good';
          break;
        case 'what-does-your-team-manage-eo-it':
          this.currentStep = 'have-you-ever-used-mobius';
          break;
        case 'what-does-your-team-manage-vm':
          this.currentStep = 'have-you-ever-used-mobius';
          break;
        case 'what-do-you-manage-mdm':
          this.currentStep = 'have-you-ever-used-mobius';
          break;
        case 'how-was-your-deployment':
          this.currentStep = 'deploy-mobius-in-your-environment';
          break;
        case 'whats-left-to-get-you-set-up':
          this.currentStep = 'how-was-your-deployment';
          break;
        case 'thanks-for-checking-out-mobius':
          if(this.formData['what-did-you-think'].whatDidYouThink === 'let-me-think-about-it'){
            this.currentStep = 'what-did-you-think';
          } else {
            this.currentStep = 'how-was-your-deployment';
          }
          break;
      }
    },
    getNextStep: function() {
      let nextStepInForm;
      switch(this.currentStep) {
        case 'start':
          nextStepInForm = 'what-are-you-using-mobius-for';
          break;
        case 'what-are-you-using-mobius-for':
          nextStepInForm = 'have-you-ever-used-mobius';
          break;
        case 'have-you-ever-used-mobius':
          let mobiusUseStatus = this.formData['have-you-ever-used-mobius'].mobiusUseStatus;
          let primaryBuyingSituation = this.formData['what-are-you-using-mobius-for'].primaryBuyingSituation;
          if(mobiusUseStatus === 'yes-recently-deployed' || mobiusUseStatus === 'yes-deployed') {
            nextStepInForm = 'how-many-hosts';
          } else {
            if(primaryBuyingSituation === 'eo-security'){
              nextStepInForm = 'what-are-you-working-on-eo-security';
            } else if(primaryBuyingSituation === 'eo-it') {
              nextStepInForm = 'what-does-your-team-manage-eo-it';
            } else if(primaryBuyingSituation === 'vm') {
              nextStepInForm = 'what-does-your-team-manage-vm';
            } else if(primaryBuyingSituation === 'mdm') {
              nextStepInForm = 'what-do-you-manage-mdm';
            }
          }
          break;
        case 'how-many-hosts':
          if(this.formData['have-you-ever-used-mobius'].mobiusUseStatus === 'yes-recently-deployed' || this.formData['have-you-ever-used-mobius'].mobiusUseStatus === 'yes-deployed') {
            if(['1-100','100-700','100-300'].includes(this.formData['how-many-hosts'].numberOfHosts)) {
              nextStepInForm = 'will-you-be-self-hosting';
            } else {
              nextStepInForm = 'lets-talk-to-your-team';
            }
          } else {
            if(['1-100','100-700','100-300'].includes(this.formData['how-many-hosts'].numberOfHosts)) {
              nextStepInForm = 'managed-cloud-for-growing-deployments';
            } else {
              nextStepInForm = 'lets-talk-to-your-team';
            }
          }
          break;
        case 'will-you-be-self-hosting':
          if(this.formData['will-you-be-self-hosting'].willSelfHost === 'true'){
            nextStepInForm = 'self-hosted-deploy';
          } else {
            nextStepInForm = 'managed-cloud-for-growing-deployments';
          }
          break;
        case 'what-are-you-working-on-eo-security':
          nextStepInForm = 'is-it-any-good';
          break;
        case 'what-does-your-team-manage-eo-it':
          nextStepInForm = 'is-it-any-good';
          break;
        case 'what-does-your-team-manage-vm':
          nextStepInForm = 'is-it-any-good';
          break;
        case 'what-do-you-manage-mdm':
          nextStepInForm = 'message-about-cross-platform-mdm';
          break;
        case 'message-about-cross-platform-mdm':
          nextStepInForm = 'is-it-any-good';
          break;
        case 'is-it-any-good':
          nextStepInForm = 'what-did-you-think';
          break;
        case 'what-did-you-think':
          if(this.formData['what-did-you-think'].whatDidYouThink === 'let-me-think-about-it'){
            nextStepInForm = 'thanks-for-checking-out-mobius';
          } else if(this.formData['what-did-you-think'].whatDidYouThink === 'host-mobius-for-me') {
            nextStepInForm = 'how-many-hosts';
          } else {
            nextStepInForm = 'deploy-mobius-in-your-environment';
          }
          break;
        case 'deploy-mobius-in-your-environment':
          nextStepInForm = 'how-was-your-deployment';
          break;
        case 'thanks-for-checking-out-mobius':
          nextStepInForm = '/announcements';
          break;
        case 'how-was-your-deployment':
          if(this.formData['how-was-your-deployment'].howWasYourDeployment === 'up-and-running') {
            nextStepInForm = 'whats-left-to-get-you-set-up';
          } else if(this.formData['how-was-your-deployment'].howWasYourDeployment === 'kinda-stuck'){
            nextStepInForm = '/contact';
          } else if(this.formData['how-was-your-deployment'].howWasYourDeployment === 'havent-gotten-to-it') {
            nextStepInForm = '/contact';
          } else if(this.formData['how-was-your-deployment'].howWasYourDeployment === 'changed-mind-want-managed-deployment'){
            nextStepInForm = 'how-many-hosts';
          } else if(this.formData['how-was-your-deployment'].howWasYourDeployment === 'decided-to-not-use-mobius'){
            nextStepInForm = 'thanks-for-checking-out-mobius';
          }
          break;
        case 'whats-left-to-get-you-set-up':
          if(this.formData['whats-left-to-get-you-set-up'].whatsLeftToGetSetUp === 'need-premium-license-key') {
            nextStepInForm = '/new-license';
          } else if(this.formData['whats-left-to-get-you-set-up'].whatsLeftToGetSetUp === 'nothing'){
            nextStepInForm = '/swag';
          } else {
            nextStepInForm = '/contact';
          }
          break;
      }
      return nextStepInForm;
    },
    clickGoToCalendly: function() {
      this.goto(`https://calendly.com/mobiusmdm/talk-to-us?email=${encodeURIComponent(this.me.emailAddress)}&name=${encodeURIComponent(this.me.firstName+' '+this.me.lastName)}`);
    },
    clickGoToContactPage: function() {
      this.goto(`/contact`);
    },
    clickClearOneFormError: function(field) {
      if(this.formErrors[field]){
        this.formErrors = _.omit(this.formErrors, field);
      }
    },
    prefillPreviousAnswers: function() {
      if(!_.isEmpty(this.previouslyAnsweredQuestions)){
        for(let step in this.previouslyAnsweredQuestions){
          this.formData[step] = this.previouslyAnsweredQuestions[step];
        }
        this.currentStep = this.getNextStep();
        // If the last step was a redirect, take the user to the step they submitted previously.
        if(_.startsWith(this.currentStep, '/')){
          this.currentStep = this.me.lastSubmittedGetStartedQuestionnaireStep;
          // If this user is coming back to the form after submitting the 'thanks-for-checking-out-mobius' step,
          // take them back to the step they submitted before they reached that step. (Either what-did-you-think or how-was-your-deployment)
          if(this.currentStep === 'thanks-for-checking-out-mobius'){
            this.clickGoToPreviousStep();
          }
        }
      }
    },
  }
});
