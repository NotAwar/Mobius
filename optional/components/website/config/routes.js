/**
 * Route Mappings
 * (sails.config.routes)
 *
 * Your routes tell Sails what to do each time it receives a request.
 *
 * For more information on configuring custom routes, check out:
 * https://sailsjs.com/anatomy/config/routes-js
 */

module.exports.routes = {

  //  ╦ ╦╔═╗╔╗ ╔═╗╔═╗╔═╗╔═╗╔═╗
  //  ║║║║╣ ╠╩╗╠═╝╠═╣║ ╦║╣ ╚═╗
  //  ╚╩╝╚═╝╚═╝╩  ╩ ╩╚═╝╚═╝╚═╝
  'GET /': {
    action: 'view-homepage-or-redirect',
    locals: {
      isHomepage: true,
      showHeaderCTA: true,
    }
  },

  'GET /try-mobius': {
    action: 'view-mobiuscli-preview',
    locals: {
      hideHeaderLinks: true,
      hideFooterLinks: true,
      pageTitleForMeta: 'mobiuscli preview',
      pageDescriptionForMeta: 'Learn about getting started with Mobius using mobiuscli.'
    }
  },


  'GET /logos': {
    action: 'view-press-kit',
    locals: {
      pageTitleForMeta: 'Logos',
      pageDescriptionForMeta: 'Download Mobius logos, wallpapers, and screenshots.'
    }
  },

  'GET /queries': {
    action: 'view-query-library',
    locals: {
      currentSection: 'documentation',
      pageTitleForMeta: 'Queries',
      pageDescriptionForMeta: 'A growing collection of optional queries you can run anytime to ask questions about your devices using Mobius and osquery.'
    }
  },

  'GET /queries/:slug': {
    action: 'view-query-detail',// Meta title and description set in view action
    locals: {
      currentSection: 'documentation',
    }
  },

  'GET /vitals/:slug': {
    action: 'view-vital-details',// Meta title and description set in view action
    locals: {
      currentSection: 'documentation',
    }
  },

  'GET /policies': {
    action: 'view-policy-library',
    locals: {
      currentSection: 'documentation',
      pageTitleForMeta: 'Policies',
      pageDescriptionForMeta: 'A growing collection of useful controls and policies for organizations deploying Mobius and osquery.'
    }
  },
  'GET /policies/:slug': {
    action: 'view-policy-details',// Meta title and description set in view action
    locals: {
      currentSection: 'documentation',
    }
  },



  'GET /docs/?*': {
    skipAssets: false,
    action: 'docs/view-basic-documentation',// Meta title and description set in view action
    locals: {
      hideStartCTA: true,
      currentSection: 'documentation',
    }
  },// handles /docs and /docs/foo/bar



  'GET /new-license': {
    action: 'customers/view-new-license',
    locals: {
      hideHeaderLinks: true,
      hideFooterLinks: true,
      hideStartCTA: true,
      pageTitleForMeta: 'Get Mobius Premium',
      pageDescriptionForMeta: 'Generate your quote and start using Mobius Premium today.',
    }
  },
  'GET /register': {
    action: 'entrance/view-signup',
    locals: {
      hideFooterLinks: true,
      hideStartCTA: true,
      pageTitleForMeta: 'Sign up',
      pageDescriptionForMeta: 'Sign up for a Mobius account.',
    }
  },
  'GET /login': {
    action: 'entrance/view-login',
    locals: {
      hideFooterLinks: true,
      hideStartCTA: true,
      pageTitleForMeta: 'Log in',
      pageDescriptionForMeta: 'Log in to Mobius.',
    }
  },
  'GET /customers/dashboard': {
    action: 'customers/view-dashboard',
    locals: {
      hideHeaderLinks: true,
      hideFooterLinks: true,
      hideStartCTA: true,
      pageTitleForMeta: 'Customer dashboard',
      pageDescriptionForMeta: 'View and edit information about your Mobius Premium license.',
    }
  },
  'GET /customers/update-subscription': { action: 'customers/redirect-to-stripe-billing-portal' },
  'GET /customers/forgot-password': {
    action: 'entrance/view-forgot-password',
    locals: {
      hideHeaderLinks: true,
      hideFooterLinks: true,
      hideStartCTA: true,
      pageTitleForMeta: 'Forgot password',
      pageDescriptionForMeta: 'Recover the password for your Mobius customer account.',
    }
  },
  'GET /customers/new-password': {
    action: 'entrance/view-new-password',
    locals: {
      hideHeaderLinks: true,
      hideFooterLinks: true,
      hideStartCTA: true,
      pageTitleForMeta: 'New password',
      pageDescriptionForMeta: 'Change the password for your Mobius customer account.',
    }
  },

  'GET /reports/state-of-device-management': {
    action: 'reports/view-state-of-device-management',
    locals: {
      pageTitleForMeta: 'State of device management',
      pageDescriptionForMeta: 'We surveyed 200+ security practitioners to discover the state of device management in 2022. Click here to learn about their struggles and best practices.',
    }
  },

  'GET /admin/email-preview': {
    action: 'admin/view-email-templates',
    locals: {
      hideFooterLinks: true,
      showAdminLinks: true,
      hideStartCTA: true,
    },
  },

  'GET /admin/email-preview/*': {
    action: 'admin/view-email-template-preview',
    skipAssets: true,
    locals: {
      hideFooterLinks: true,
      showAdminLinks: true,
      hideStartCTA: true,
    },
  },

  'GET /admin/sandbox-waitlist': {
    action: 'admin/view-sandbox-waitlist',
    locals: {
      hideFooterLinks: true,
      showAdminLinks: true,
      hideStartCTA: true,
    },
  },

  'GET /tables/:tableName': {
    action: 'view-osquery-table-details',// Meta title and description set in view action
    locals: {
      currentSection: 'documentation',
    }
  },

  'GET /admin/generate-license': {
    action: 'admin/view-generate-license',
    locals: {
      hideFooterLinks: true,
      showAdminLinks: true,
      hideStartCTA: true,
    }
  },


  'GET /connect-vanta': {
    action: 'view-connect-vanta',
  },

  'GET /vanta-authorization': {
    action: 'view-vanta-authorization',
  },

  'GET /device-management': {
    action: 'view-device-management',
    locals: {
      pageTitleForMeta: 'Device management (MDM)',
      pageDescriptionForMeta: 'Manage your devices in any browser or use git to make changes as code.',
      currentSection: 'platform',
    }
  },

  'GET /orchestration': {
    action: 'view-observability',
    locals: {
      pageTitleForMeta: 'Orchestration',
      pageDescriptionForMeta: 'Pulse check anything, build reports, and ship data to any platform with Mobius.',
      currentSection: 'platform',
    }
  },

  'GET /software-management': {
    action: 'view-software-management',
    locals: {
      pageTitleForMeta: 'Software management',
      pageDescriptionForMeta: 'Pick from a curated app library or upload your own custom packages. Configure custom installation scripts if you need or let Mobius do it for you.',
      currentSection: 'platform',
    }
  },

  'GET /support': {
    action: 'view-support',
    locals: {
      pageTitleForMeta: 'Support',
      pageDescriptionForMeta: 'Ask a question, chat with engineers, or get in touch with the Mobius team.',
      currentSection: 'documentation',
    }
  },

  'GET /integrations': {
    action: 'view-integrations',
    locals: {
      pageTitleForMeta: 'Integrations',
      pageDescriptionForMeta: 'Integrate IT ticketing systems, SIEM and SOAR platforms, custom IT workflows, and more.',
      currentSection: 'platform'
    }
  },

  'GET /start': {
    action: 'view-start',
    locals: {
      hideFooterLinks: true,
      hideGetStartedButton: true,
      hideStartCTA: true,
      pageTitleForMeta: 'Start',
      pageDescriptionForMeta: 'Get Started with Mobius. Spin up a local demo or get your Premium license key.',
    }
  },

  'GET /better': {
    action: 'view-transparency',
    locals: {
      pageDescriptionForMeta: 'Discover how Mobius simplifies IT and security, prioritizing privacy, transparency, and trust for end users.',
      pageTitleForMeta: 'Better with Mobius',
      hideStartCTA: true,
    }
  },

  'GET /deals': {
    action: 'view-deals',
    locals: {
      pageTitleForMeta: 'Deal registration',
      pageDescriptionForMeta: 'Register an opportunity with a potential customer.',
      hideFooterLinks: true,
      hideStartCTA: true,
    }
  },

  'GET /testimonials': {
    action: 'view-testimonials',
    locals: {
      pageTitleForMeta: 'What people are saying',
      pageDescriptionForMeta: 'See what people are saying about Mobius.'
    }
  },

  'GET /app-library': {
    action: 'view-app-library',
    locals: {
      pageTitleForMeta: 'Software',
      pageDescriptionForMeta: 'Install Mobius-maintained apps on your hosts without the need for additional configuration. Activate self-service for your end users.',
    }
  },

  'GET /app-library/:appIdentifier': {
    action: 'view-app-details',// Meta title and description set in view action
  },

  'GET /meetups': {
    action: 'view-meetups',
    locals: {
      pageTitleForMeta: 'Meetups',
      pageDescriptionForMeta: 'See upcoming meetup locations.',
    }
  },

  'GET /query-generator': {
    action: 'query-generator/view-query-generator',
    locals: {
      showAdminLinks: true,
    }
  },

  'GET /os-settings': {
    action: 'view-os-settings',
    locals: {
      currentSection: 'documentation',
      pageTitleForMeta: 'OS settings',
      pageDescriptionForMeta: 'Generate OS settings in CSP, .mobileconfig, and DDM format',
    }
  },


  'GET /configuration-builder': {
    action: 'view-configuration-builder',
    locals: {
      showConfigurationProfileLayout: true,
      hideStartCTA: true,
    }
  },

  'GET /microsoft-compliance-partner/remediate': {
    action: 'microsoft-proxy/view-remediate',
    locals: {
      showConfigurationProfileLayout: true,
      hideStartCTA: true,
    }
  },

  'GET /microsoft-compliance-partner/enroll': {
    action: 'microsoft-proxy/view-turn-on-mdm',
    locals: {
      showConfigurationProfileLayout: true,
      hideStartCTA: true,
    }
  },

  //  ╦  ╔═╗╔═╗╔═╗╔═╗╦ ╦  ╦═╗╔═╗╔╦╗╦╦═╗╔═╗╔═╗╔╦╗╔═╗
  //  ║  ║╣ ║ ╦╠═╣║  ╚╦╝  ╠╦╝║╣  ║║║╠╦╝║╣ ║   ║ ╚═╗
  //  ╩═╝╚═╝╚═╝╩ ╩╚═╝ ╩   ╩╚═╚═╝═╩╝╩╩╚═╚═╝╚═╝ ╩ ╚═╝
  //  ┌─  ┌─┐┌─┐┬─┐  ┌┐ ┌─┐┌─┐┬┌─┬ ┬┌─┐┬─┐┌┬┐┌─┐  ┌─┐┌─┐┌┬┐┌─┐┌─┐┌┬┐  ─┐
  //  │   ├┤ │ │├┬┘  ├┴┐├─┤│  ├┴┐│││├─┤├┬┘ ││└─┐  │  │ ││││├─┘├─┤ │    │
  //  └─  └  └─┘┴└─  └─┘┴ ┴└─┘┴ ┴└┴┘┴ ┴┴└──┴┘└─┘  └─┘└─┘┴ ┴┴  ┴ ┴ ┴o  ─┘
  // Add redirects here for deprecated/legacy links, so that they go to an appropriate new place instead of just being broken when pages move or get renamed.
  //
  // For example:
  // If we were going to change mobiusmdm.com/company/about to mobiusmdm.com/company/story, we might do something like:
  // ```
  // 'GET /company/about': '/company/story',
  // ```
  //
  // Or another example, if we were to rename a doc page:
  // ```
  // 'GET /docs/using-mobius/learn-how-to-use-mobius': '/docs/using-mobius/mobius-for-beginners',
  // ```
  'GET /customer-stories': '/testimonials',
  'GET /try': '/get-started',
  'GET /docs/deploying/mobius-public-load-testing': '/docs/deploying/load-testing',
  'GET /guides/deploying-mobius-on-aws-with-terraform': '/deploy/deploying-mobius-on-aws-with-terraform',
  'GET /guides/deploying-mobius-on-render': '/deploy/deploying-mobius-on-render',
  'GET /use-cases/correlate-network-connections-with-community-id-in-osquery': '/guides/correlate-network-connections-with-community-id-in-osquery',
  'GET /use-cases/converting-unix-timestamps-with-osquery': '/guides/converting-unix-timestamps-with-osquery',
  'GET /use-cases/ebpf-the-future-of-osquery-on-linux': '/securing/ebpf-the-future-of-osquery-on-linux',
  'GET /use-cases/mobius-quick-tips-querying-procdump-eula-has-been-accepted': '/guides/mobius-quick-tips-querying-procdump-eula-has-been-accepted',
  'GET /use-cases/generate-process-trees-with-osquery': '/guides/generate-process-trees-with-osquery',
  'GET /use-cases/get-and-stay-compliant-across-your-devices-with-mobius': '/securing/get-and-stay-compliant-across-your-devices-with-mobius',
  'GET /use-cases/import-and-export-queries-and-packs-in-mobius': '/guides/import-and-export-queries-and-packs-in-mobius',
  'GET /guides/import-and-export-queries-and-packs-in-mobius': '/guides/import-and-export-queries-in-mobius',
  'GET /guides/deploy-security-agents': '/guides/deploy-software-packages',
  'GET /use-cases/locate-assets-with-osquery': '/guides/locate-assets-with-osquery',
  'GET /use-cases/osquery-a-tool-to-easily-ask-questions-about-operating-systems': '/guides/osquery-a-tool-to-easily-ask-questions-about-operating-systems',
  'GET /use-cases/osquery-consider-joining-against-the-users-table': '/guides/osquery-consider-joining-against-the-users-table',
  'GET /use-cases/stay-on-course-with-your-security-compliance-goals': '/guides/stay-on-course-with-your-security-compliance-goals',
  'GET /use-cases/using-elasticsearch-and-kibana-to-visualize-osquery-performance': '/guides/using-elasticsearch-and-kibana-to-visualize-osquery-performance',
  'GET /use-cases/work-may-be-watching-but-it-might-not-be-as-bad-as-you-think': '/securing/work-may-be-watching-but-it-might-not-be-as-bad-as-you-think',
  'GET /docs/contributing/testing':  '/docs/contributing/getting-started/testing-and-local-development',
  'GET /device-management/mobius-user-stories-f100': '/success-stories/mobius-user-stories-wayfair',
  'GET /device-management/mobius-user-stories-schrodinger': '/success-stories/mobius-user-stories-wayfair',
  'GET /device-management/mobius-user-stories-wayfair': '/success-stories/mobius-user-stories-wayfair',
  'GET /docs/using-mobius/mdm-macos-settings': '/docs/using-mobius/mdm-custom-macos-settings',
  'GET /platform': '/',
  'GET /docs': '/docs/get-started/why-mobius',
  'GET /docs/get-started': '/docs/get-started/why-mobius',
  'GET /docs/rest-api': '/docs/rest-api/rest-api',
  'GET /docs/configuration': '/docs/configuration/mobius-server-configuration',
  'GET /docs/contributing': 'https://github.com/notawar/mobius/tree/main/docs/Contributing',
  'GET /docs/deploy': '/docs/deploy/introduction',
  'GET /docs/using-mobius/faq': '/docs/get-started/faq',
  'GET /docs/using-mobius/monitoring-mobius': '/docs/deploy/monitoring-mobius',
  'GET /docs/using-mobius/adding-hosts': '/docs/using-mobius/enroll-hosts#install-mobiusdaemon',
  'GET /docs/using-mobius/mobiusdaemon': '/docs/using-mobius/enroll-hosts',
  'GET /docs/using-mobius/teams': '/docs/using-mobius/segment-hosts',
  'GET /docs/using-mobius/permissions': '/docs/using-mobius/manage-access',
  'GET /docs/using-mobius/chromeos': '/docs/using-mobius/enroll-chromebooks',
  'GET /docs/using-mobius/rest-api': '/docs/rest-api/rest-api',
  'GET /docs/using-mobius/configuration-files': '/docs/configuration/configuration-files/',
  'GET /docs/using-mobius/process-file-events': '/guides/querying-process-file-events-table-on-centos-7',
  'GET /docs/using-mobius/audit-activities': '/docs/using-mobius/audit-logs',
  'GET /docs/using-mobius/detail-queries-summary': '/docs/using-mobius/understanding-host-vitals',
  'GET /docs/using-mobius/orbit': '/docs/using-mobius/enroll-hosts',
  'GET /docs/deploying': '/docs/deploy',
  'GET /docs/deploying/faq': '/docs/get-started/faq',
  'GET /docs/deploying/introduction': '/docs/deploy/introduction',
  'GET /docs/deploy/introduction': '/docs/deploy/deploy-mobius',
  'GET /docs/deploying/reference-architectures': '/docs/deploy/reference-architectures',
  'GET /docs/deploying/upgrading-mobius': '/docs/deploy/upgrading-mobius',
  'GET /docs/deploying/server-installation': '/docs/deploy/server-installation',
  'GET /docs/deploying/cloudgov': '/docs/deploy/cloudgov',
  'GET /docs/deploying/configuration': '/docs/configuration/mobius-server-configuration',
  'GET /docs/deploying/mobiuscli-agent-updates': '/docs/using-mobius/update-agents',
  'GET /docs/contributing/configuration': '/docs/configuration/configuration-files',
  'GET /docs/contributing/*': {
    skipAssets: true,
    fn: (req, res)=>{
      return res.redirect('https://github.com/notawar/mobius/tree/main/docs/Contributing');
    }
  },
  'GET /docs/contributing/orbit-development-and-release-strategy': '/docs/contributing/workflows/mobiusdaemon-development-and-release-strategy',
  'GET /docs/contributing/run-locally-built-orbit': '/docs/contributing/getting-started/run-locally-built-mobiusdaemon',
  'GET /deploy/deploying-mobius-on-render': '/docs/deploy/deploy-on-render',
  'GET /deploy/deploy-mobius-on-hetzner-cloud': '/docs/deploy/deploy-on-hetzner-cloud',
  'GET /deploy': '/docs/deploy',
  'GET /deploy/deploying-mobius-on-aws-with-terraform': '/docs/deploy/deploy-on-aws-with-terraform',
  'GET /docs/deploy/server-installation': '/docs/deploy/introduction',
  'GET /osquery-management': '/endpoint-ops',
  'GET /guides/using-github-actions-to-apply-configuration-profiles-with-mobius': 'https://github.com/notawar/mobius-gitops',
  'GET /docs/using-mobius/mdm-macos-updates': '/docs/using-mobius/mdm-os-updates',
  'GET /example-windows-profile': 'https://github.com/notawar/mobius-gitops/blob/860dcf2609e2b25a6d6becf8006a7118a19cd615/lib/windows-screenlock.xml',// « resuable link for OS settings doc page
  'GET /docs/using-mobius/mdm-custom-macos-settings': '/docs/using-mobius/mdm-custom-os-settings',
  'GET /customers/login': '/login',
  'GET /customers/register': '/register',
  'GET /try-mobius/login': '/login',
  'GET /try-mobius/register': '/register',
  'GET /customers/new-license': '/new-license',
  'GET /try-mobius/mobiuscli-preview': '/try-mobius',
  'GET /upgrade': '/pricing',
  'GET /docs/deploy/system-d': '/docs/deploy/reference-architectures#systemd',
  'GET /docs/deploy/proxies': '/docs/deploy/reference-architectures#using-a-proxy',
  'GET /docs/deploy/public-ip': '/docs/deploy/reference-architectures#public-ips-of-devices',
  'GET /docs/deploy/monitoring-mobius': '/docs/deploy/reference-architectures#monitoring-mobius',
  'GET /docs/deploy/deploy-mobius-on-aws-ecs': '/guides/deploy-mobius-on-aws-ecs',
  'GET /docs/deploy/deploy-mobius-on-centos': '/guides/deploy-mobius-on-centos',
  'GET /docs/deploy/cloudgov': '/guides/deploy-mobius-on-cloudgov',
  'GET /docs/deploy/deploy-on-aws-with-terraform': '/guides/deploy-mobius-on-aws-with-terraform',
  'GET /docs/deploy/deploy-on-hetzner-cloud': '/guides/deploy-mobius-on-hetzner-cloud',
  'GET /docs/deploy/deploy-on-render': '/guides/deploy-mobius-on-render',
  'GET /docs/deploy/deploy-mobius-on-kubernetes': '/guides/deploy-mobius-on-kubernetes',
  'GET /docs/using-mobius/mdm-macos-setup': '/docs/using-mobius/mdm-setup',
  'GET /transparency': '/better',
  'GET /docs/configuration/configuration-files': '/docs/using-mobius/gitops',
  'GET /try-mobius/explore-data': '/tables/account_policy_data',
  'GET /try-mobius/explore-data/:hostPlatform/:tableName': {
    fn: (req, res)=>{
      return res.redirect('/tables/'+req.param('tableName'));
    }
  },
  'GET /docs/using-mobius/mobius-ui': (req,res)=> { return res.redirect(301, '/guides/queries');},
  'GET /docs/using-mobius/learn-how-to-use-mobius': (req,res)=> { return res.redirect(301, '/guides/queries');},
  'GET /docs/using-mobius/mobiuscli-cli': (req,res)=> { return res.redirect(301, '/guides/mobiuscli');},
  'GET /docs/using-mobius/mobius-desktop': (req,res)=> { return res.redirect(301, '/guides/mobius-desktop');},
  'GET /docs/using-mobius/enroll-hosts': (req,res)=> { return res.redirect(301, '/guides/enroll-hosts');},
  'GET /docs/using-mobius/manage-access': (req,res)=> { return res.redirect(301, '/guides/role-based-access');},
  'GET /docs/using-mobius/segment-hosts': (req,res)=> { return res.redirect(301, '/guides/teams');},
  'GET /docs/using-mobius/supported-browsers': (req,res)=> { return res.redirect(301, '/docs/get-started/faq');},
  'GET /docs/using-mobius/supported-host-operating-systems': (req,res)=> { return res.redirect(301, '/docs/get-started/faq');},
  'GET /docs/using-mobius/gitops': (req,res)=> { return res.redirect(301, '/docs/configuration/yaml-files');},
  'GET /docs/using-mobius/mdm-setup': (req,res)=> { return res.redirect(301, '/guides/macos-mdm-setup');},
  'GET /docs/using-mobius/mdm-migration-guide': (req,res)=> { return res.redirect(301, '/guides/mdm-migration');},
  'GET /docs/using-mobius/mdm-os-updates': (req,res)=> { return res.redirect(301, '/guides/enforce-os-updates');},
  'GET /docs/using-mobius/mdm-disk-encryption': (req,res)=> { return res.redirect(301, '/guides/enforce-disk-encryption');},
  'GET /docs/using-mobius/mdm-custom-os-settings': (req,res)=> { return res.redirect(301, '/guides/custom-os-settings');},
  'GET /docs/using-mobius/mdm-macos-setup-experience': (req,res)=> { return res.redirect(301, '/guides/macos-setup-experience');},
  'GET /docs/using-mobius/scripts': (req,res)=> { return res.redirect(301, '/guides/scripts');},
  'GET /docs/using-mobius/automations': (req,res)=> { return res.redirect(301, '/guides/automations');},
  'GET /docs/using-mobius/puppet-module': (req,res)=> { return res.redirect(301, '/guides/puppet-module');},
  'GET /docs/using-mobius/vulnerability-processing': (req,res)=> { return res.redirect(301, '/guides/vulnerability-processing');},
  'GET /docs/using-mobius/cis-benchmarks': (req,res)=> { return res.redirect(301, '/guides/cis-benchmarks');},
  'GET /docs/using-mobius/osquery-process': (req,res)=> { return res.redirect(301, '/guides/osquery-watchdog');},
  'GET /docs/using-mobius/update-agents': (req,res)=> { return res.redirect(301, '/guides/mobiusdaemon-updates');},
  'GET /docs/using-mobius/usage-statistics': (req,res)=> { return res.redirect(301, '/guides/mobius-usage-statistics');},
  'GET /docs/using-mobius/downgrading-mobius': (req,res)=> { return res.redirect(301, '/guides/downgrade-mobius');},
  'GET /docs/using-mobius/enroll-chromebooks': (req,res)=> { return res.redirect(301, '/guides/chrome-os');},
  'GET /docs/using-mobius/audit-logs': (req,res)=> { return res.redirect(301, 'https://github.com/notawar/mobius/blob/main/docs/Contributing/reference/audit-logs.md');},
  'GET /docs/using-mobius/understanding-host-vitals': (req,res)=> { return res.redirect(301, 'https://github.com/notawar/mobius/blob/main/docs/Contributing/product-groups/orchestration/understanding-host-vitals.md');},
  'GET /docs/using-mobius/standard-query-library': (req,res)=> { return res.redirect(301, '/guides/standard-query-library');},
  'GET /docs/using-mobius/mdm-commands': (req,res)=> { return res.redirect(301, '/guides/mdm-commands');},
  'GET /docs/using-mobius/log-destinations': (req,res)=> { return res.redirect(301, '/guides/log-destinations');},
  'GET /guides/how-to-uninstall-osquery': (req,res)=> { return res.redirect(301, '/guides/how-to-uninstall-mobiusdaemon');},
  'GET /guides/sysadmin-diaries-lost-device': (req,res)=> { return res.redirect(301, '/guides/lock-wipe-hosts');},
  'GET /guides/secret-variables': '/guides/secrets-in-scripts-and-configuration-profiles',
  'GET /guides/ndes-scep-proxy': '/guides/connect-end-user-to-wifi-with-certificate',
  'GET /guides/install-mobius-maintained-apps-on-macos-hosts': '/guides/mobius-maintained-apps',

  // Release note article redirects.
  'GET /releases/mobius-3.10.0': '/releases/mobius-3-10-0',
  'GET /releases/mobius-3.12.0': '/releases/mobius-3-12-0',
  'GET /releases/mobius-3.13.0': '/releases/mobius-3-13-0',
  'GET /releases/mobius-3.5.0': '/releases/mobius-3-5-0',
  'GET /releases/mobius-3.6.0': '/releases/mobius-3-6-0',
  'GET /releases/mobius-3.7.1': '/releases/mobius-3-7-1',
  'GET /releases/mobius-3.8.0': '/releases/mobius-3-8-0',
  'GET /releases/mobius-3.9.0': '/releases/mobius-3-9-0',
  'GET /releases/mobius-4.0.0': '/releases/mobius-4-0-0',
  'GET /releases/mobius-4.1.0': '/releases/mobius-4-1-0',
  'GET /releases/mobius-4.10.0': '/releases/mobius-4-10-0',
  'GET /releases/mobius-4.12.0': '/releases/mobius-4-12-0',
  'GET /releases/mobius-4.11.0': '/releases/mobius-4-11-0',
  'GET /releases/mobius-4.13.0': '/releases/mobius-4-13-0',
  'GET /releases/mobius-4.15.0': '/releases/mobius-4-15-0',
  'GET /releases/mobius-3.11.0': '/releases/mobius-3-11-0',
  'GET /releases/mobius-4.16.0': '/releases/mobius-4-16-0',
  'GET /releases/mobius-4.17.0': '/releases/mobius-4-17-0',
  'GET /releases/mobius-4.18.0': '/releases/mobius-4-18-0',
  'GET /releases/mobius-4.19.0': '/releases/mobius-4-19-0',
  'GET /releases/mobius-4.2.0': '/releases/mobius-4-2-0',
  'GET /releases/mobius-4.21.0': '/releases/mobius-4-21-0',
  'GET /releases/mobius-4.14.0': '/releases/mobius-4-14-0',
  'GET /releases/mobius-4.22.0': '/releases/mobius-4-22-0',
  'GET /releases/mobius-4.20.0': '/releases/mobius-4-20-0',
  'GET /releases/mobius-4.23.0': '/releases/mobius-4-23-0',
  'GET /releases/mobius-4.24.0': '/releases/mobius-4-24-0',
  'GET /releases/mobius-4.25.0': '/releases/mobius-4-25-0',
  'GET /releases/mobius-4.27.0': '/releases/mobius-4-27-0',
  'GET /releases/mobius-4.26.0': '/releases/mobius-4-26-0',
  'GET /releases/mobius-4.28.0': '/releases/mobius-4-28-0',
  'GET /releases/mobius-4.29.0': '/releases/mobius-4-29-0',
  'GET /releases/mobius-4.30.0': '/releases/mobius-4-30-0',
  'GET /releases/mobius-4.31.0': '/releases/mobius-4-31-0',
  'GET /releases/mobius-4.3.0': '/releases/mobius-4-3-0',
  'GET /releases/mobius-4.32.0': '/releases/mobius-4-32-0',
  'GET /releases/mobius-4.33.0': '/releases/mobius-4-33-0',
  'GET /releases/mobius-4.34.0': '/releases/mobius-4-34-0',
  'GET /releases/mobius-4.36.0': '/releases/mobius-4-36-0',
  'GET /releases/mobius-4.38.0': '/releases/mobius-4-38-0',
  'GET /releases/mobius-4.39.0': '/releases/mobius-4-39-0',
  'GET /releases/mobius-4.35.0': '/releases/mobius-4-35-0',
  'GET /releases/mobius-4.4.0': '/releases/mobius-4-4-0',
  'GET /releases/mobius-4.37.0': '/releases/mobius-4-37-0',
  'GET /releases/mobius-4.40.0': '/releases/mobius-4-40-0',
  'GET /releases/mobius-4.42.0': '/releases/mobius-4-42-0',
  'GET /releases/mobius-4.43.0': '/releases/mobius-4-43-0',
  'GET /releases/mobius-4.44.0': '/releases/mobius-4-44-0',
  'GET /releases/mobius-4.41.0': '/releases/mobius-4-41-0',
  'GET /releases/mobius-4.45.0': '/releases/mobius-4-45-0',
  'GET /releases/mobius-4.46.0': '/releases/mobius-4-46-0',
  'GET /releases/mobius-4.47.0': '/releases/mobius-4-47-0',
  'GET /releases/mobius-4.49.0': '/releases/mobius-4-49-0',
  'GET /releases/mobius-4.5.0': '/releases/mobius-4-5-0',
  'GET /releases/mobius-4.50.0': '/releases/mobius-4-50-0',
  'GET /releases/mobius-4.51.0': '/releases/mobius-4-51-0',
  'GET /releases/mobius-4.48.0': '/releases/mobius-4-48-0',
  'GET /releases/mobius-4.53.0': '/releases/mobius-4-53-0',
  'GET /releases/mobius-4.55.0': '/releases/mobius-4-55-0',
  'GET /releases/mobius-4.56.0': '/releases/mobius-4-56-0',
  'GET /releases/mobius-4.54.0': '/releases/mobius-4-54-0',
  'GET /releases/mobius-4.58.0': '/releases/mobius-4-58-0',
  'GET /releases/mobius-4.59.0': '/releases/mobius-4-59-0',
  'GET /releases/mobius-4.57.0': '/releases/mobius-4-57-0',
  'GET /releases/mobius-4.6.0': '/releases/mobius-4-6-0',
  'GET /releases/mobius-4.60.0': '/releases/mobius-4-60-0',
  'GET /releases/mobius-4.7.0': '/releases/mobius-4-7-0',
  'GET /releases/mobius-4.8.0': '/releases/mobius-4-8-0',
  'GET /releases/mobius-4.61.0': '/releases/mobius-4-61-0',
  'GET /releases/mobius-4.9.0': '/releases/mobius-4-9-0',
  'GET /announcements/nvd-api-2.0': '/announcements/nvd-api-2-0',
  'GET /releases/osquery-5.11.0': '/releases/osquery-5-11-0',
  'GET /releases/osquery-5.8.1': '/releases/osquery-5-8-1',

  //  ╔╦╗╦╔═╗╔═╗  ╦═╗╔═╗╔╦╗╦╦═╗╔═╗╔═╗╔╦╗╔═╗   ┬   ╔╦╗╔═╗╦ ╦╔╗╔╦  ╔═╗╔═╗╔╦╗╔═╗
  //  ║║║║╚═╗║    ╠╦╝║╣  ║║║╠╦╝║╣ ║   ║ ╚═╗  ┌┼─   ║║║ ║║║║║║║║  ║ ║╠═╣ ║║╚═╗
  //  ╩ ╩╩╚═╝╚═╝  ╩╚═╚═╝═╩╝╩╩╚═╚═╝╚═╝ ╩ ╚═╝  └┘   ═╩╝╚═╝╚╩╝╝╚╝╩═╝╚═╝╩ ╩═╩╝╚═╝

  // Convenience
  // =============================================================================================================
  // Things that people are used to typing in to the URL and just randomly trying.
  //
  // For example, a clever user might try to visit mobiusmdm.com/documentation, not knowing that Mobius's website
  // puts this kind of thing under /docs, NOT /documentation.  These "convenience" redirects are to help them out.
  'GET /admin':                      '/admin/email-preview',
  'GET /renew':                      'https://calendly.com/zayhanlon/mobius-renewal-discussion',
  'GET /documentation':              '/docs',
  'GET /contribute':                 '/docs/contributing',
  'GET /install':                    '/mobiuscli-preview',
  'GET /company':                    '/company/about',
  'GET /company/contact':            '/contact',
  'GET /legal':                      '/legal/terms',
  'GET /terms':                      '/legal/terms',
  'GET /docs/using-mobius/updating-mobius': '/docs/deploying/upgrading-mobius',
  'GET /brand':                  '/logos',
  'GET /get-started':            '/try-mobius',
  'GET /g':                       (req,res)=> { let originalQueryStringWithAmp = req.url.match(/\?(.+)$/) ? '&'+req.url.match(/\?(.+)$/)[1] : ''; return res.redirect(301, sails.config.custom.baseUrl+'/?meet-mobius'+originalQueryStringWithAmp); },
  'GET /test-mobius-sandbox':     '/register',
  'GET /unsubscribe':             (req,res)=> { let originalQueryString = req.url.match(/\?(.+)$/) ? req.url.match(/\?(.+)$/)[1] : ''; return res.redirect(301, sails.config.custom.baseUrl+'/api/v1/unsubscribe-from-marketing-emails?'+originalQueryString);},
  'GET /unsubscribe-from-newsletter':             (req,res)=> { let originalQueryString = req.url.match(/\?(.+)$/) ? req.url.match(/\?(.+)$/)[1] : ''; return res.redirect(301, sails.config.custom.baseUrl+'/api/v1/unsubscribe-from-all-newsletters?'+originalQueryString);},
  'GET /tables':                 '/tables/account_policy_data',
  'GET /vitals':                 '/vitals/battery',
  'GET /imagine/launch-party':  'https://www.eventbrite.com/e/601763519887',
  'GET /blackhat2023':   'https://github.com/notawar/mobius/tree/main/tools/blackhat-mdm', // Assets from @marcosd4h & @zwass Black Hat 2023 talk
  'GET /mobiuscli-preview':   '/try-mobius',
  'GET /try-mobius/sandbox-expired':   '/try-mobius',
  'GET /try-mobius/sandbox':   '/try-mobius',
  'GET /try-mobius/waitlist':   '/try-mobius',
  'GET /endpoint-operations': '/endpoint-ops',// « just in case we type it the wrong way
  'GET /example-dep-profile': 'https://github.com/notawar/mobius/blob/main/it-and-security/lib/macos/enrollment-profiles/automatic-enrollment.dep.json',
  'GET /vulnerability-management': (req,res)=> { let originalQueryString = req.url.match(/\?(.+)$/) ? '?'+req.url.match(/\?(.+)$/)[1] : ''; return res.redirect(301, sails.config.custom.baseUrl+'/software-management'+originalQueryString);},
  'GET /endpoint-ops': (req,res)=> { let originalQueryString = req.url.match(/\?(.+)$/) ? '?'+req.url.match(/\?(.+)$/)[1] : ''; return res.redirect(301, sails.config.custom.baseUrl+'/orchestration'+originalQueryString);},
  'GET /observability': (req,res)=> { let originalQueryString = req.url.match(/\?(.+)$/) ? '?'+req.url.match(/\?(.+)$/)[1] : ''; return res.redirect(301, sails.config.custom.baseUrl+'/orchestration'+originalQueryString);},

  // Shortlinks for texting friends, radio ads, etc
  'GET /mdm': '/device-management?utm_content=mdm',// « alias for radio ad
  'GET /it': '/observability?utm_content=eo-it',
  'GET /seceng': '/observability?utm_content=eo-security',
  'GET /vm': '/software-management?utm_content=vm',

  // Mobius UI
  // =============================================================================================================
  // Redirects for external links from the Mobius UI & CLI, including to mobiusmdm.com and to external websites not
  // maintained by Mobius. These help avoid broken links by reducing surface area of links to maintain in the UI.

  'GET /learn-more-about/yaml-software': 'https://mobiusmdm.com/docs/configuration/yaml-files#software',
  'GET /learn-more-about/yaml-packages': 'https://mobiusmdm.com/docs/configuration/yaml-files#packages',
  'GET /learn-more-about/yaml-mobius-maintained-apps': 'https://mobiusmdm.com/docs/configuration/yaml-files#mobius-maintained-apps',
  'GET /learn-more-about/uninstalling-windows-software': 'https://support.microsoft.com/en-us/windows/uninstall-or-remove-apps-and-programs-in-windows-4b55f974-2cc6-2d2b-d092-5905080eaf98',
  'GET /learn-more-about/tarball-archives': 'https://mobiusmdm.com/guides/deploy-software-packages',
  'GET /learn-more-about/reinstall-software': '/guides/automatic-software-install-in-mobius#templates-for-policy-queries',
  'GET /learn-more-about/abm-apps': 'https://business.apple.com/#/main/appsandbooks',
  'GET /learn-more-about/chromeos-updates': 'https://support.google.com/chrome/a/answer/6220366',
  'GET /learn-more-about/just-in-time-provisioning': '/docs/deploy/single-sign-on-sso#just-in-time-jit-user-provisioning',
  'GET /learn-more-about/os-updates': '/docs/using-mobius/mdm-os-updates',
  'GET /sign-in-to/microsoft-automatic-enrollment-tool': 'https://portal.azure.com',
  'GET /learn-more-about/custom-os-settings': '/docs/using-mobius/mdm-custom-os-settings',
  'GET /learn-more-about/ndes': 'https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/network-device-enrollment-service-overview', // TODO: Confirm URL
  'GET /learn-more-about/setup-ndes': '/guides/ndes-scep-proxy',
  'GET /learn-more-about/certificate-authorities': '/guides/connect-end-user-to-wifi-with-certificate',
  'GET /learn-more-about/idp-email': 'https://mobiusmdm.com/docs/rest-api/rest-api#get-human-device-mapping',
  'GET /learn-more-about/enrolling-hosts': '/docs/using-mobius/adding-hosts',
  'GET /learn-more-about/setup-assistant': '/guides/macos-setup-experience#macos-setup-assistant',
  'GET /learn-more-about/policy-automations': '/docs/using-mobius/automations',
  'GET /install-wine': 'https://github.com/notawar/mobius/blob/main/it-and-security/lib/macos/scripts/install-wine.sh',
  'GET /learn-more-about/creating-service-accounts': 'https://console.cloud.google.com/projectselector2/iam-admin/serviceaccounts/create?walkthrough_id=iam--create-service-account&pli=1#step_index=1',
  'GET /learn-more-about/google-workspace-domains': 'https://admin.google.com/ac/domains/manage',
  'GET /learn-more-about/domain-wide-delegation': 'https://admin.google.com/ac/owl/domainwidedelegation',
  'GET /learn-more-about/enabling-calendar-api': 'https://console.cloud.google.com/apis/library/calendar-json.googleapis.com',
  'GET /learn-more-about/downgrading': '/docs/using-mobius/downgrading-mobius',
  'GET /learn-more-about/mobiusdaemon': '/docs/get-started/anatomy#mobiusdaemon',
  'GET /learn-more-about/rotating-enroll-secrets': 'https://github.com/notawar/mobius/blob/main/docs/Contributing/guides/cli/mobiuscli-apply.md#rotating-enroll-secrets',
  'GET /learn-more-about/audit-logs': '/docs/using-mobius/audit-logs',
  'GET /learn-more-about/calendar-events': '/announcements/mobius-in-your-calendar-introducing-maintenance-windows',
  'GET /learn-more-about/setup-windows-mdm': '/guides/windows-mdm-setup',
  'GET /learn-more-about/setup-abm': '/docs/using-mobius/mdm-setup#apple-business-manager-abm',
  'GET /learn-more-about/renew-apns': '/docs/using-mobius/mdm-setup#apple-push-notification-service-apns',
  'GET /learn-more-about/renew-abm': '/docs/using-mobius/mdm-setup#apple-business-manager-abm',
  'GET /learn-more-about/mobius-server-private-key': '/docs/configuration/mobius-server-configuration#server-private-key',
  'GET /learn-more-about/agent-options': '/docs/configuration/agent-configuration',
  'GET /learn-more-about/enable-user-collection': '/docs/using-mobius/gitops#features',
  'GET /learn-more-about/host-identifiers': '/docs/rest-api/rest-api#get-host-by-identifier',
  'GET /learn-more-about/uninstall-mobiusdaemon': '/docs/using-mobius/faq#how-can-i-uninstall-mobiusdaemon',
  'GET /learn-more-about/vulnerability-processing': '/docs/using-mobius/vulnerability-processing',
  'GET /learn-more-about/dep-profile': 'https://developer.apple.com/documentation/devicemanagement/define_a_profile',
  'GET /learn-more-about/apple-business-manager-tokens-api': '/docs/rest-api/rest-api#list-apple-business-manager-abm-tokens',
  'GET /learn-more-about/apple-business-manager-teams-api': 'https://github.com/notawar/mobius/blob/main/docs/Contributing/reference/api-for-contributors.md#update-abm-tokens-teams',
  'GET /learn-more-about/apple-business-manager-gitops': '/docs/using-mobius/gitops#apple-business-manager',
  'GET /learn-more-about/s3-bootstrap-package': '/docs/configuration/mobius-server-configuration#s-3-software-installers-bucket',
  'GET /learn-more-about/available-os-update-versions': '/guides/enforce-os-updates#available-macos-ios-and-ipados-versions',
  'GET /learn-more-about/policy-automation-install-software': '/guides/automatic-software-install-in-mobius',
  'GET /learn-more-about/query-templates-for-automatic-software-install': '/guides/automatic-software-install-in-mobius#templates-for-policy-queries',
  'GET /learn-more-about/exe-install-scripts': '/guides/exe-install-scripts',
  'GET /learn-more-about/install-scripts': '/guides/deploy-software-packages#install-script',
  'GET /learn-more-about/uninstall-scripts': '/guides/deploy-software-packages#uninstall-script',
  'GET /learn-more-about/package-metadata-extraction': '/guides/deploy-software-packages#package-metadata-extraction',
  'GET /learn-more-about/read-package-version': '/guides/deploy-software-packages#package-metadata-extraction',
  'GET /learn-more-about/mobiuscli': '/guides/mobiuscli',
  'GET /feature-request': 'https://github.com/notawar/mobius/issues/new?assignees=&labels=~feature+fest%2C%3Aproduct&projects=&template=feature-request.md&title=',
  'GET /learn-more-about/policy-automation-run-script': '/guides/policy-automation-run-script',
  'GET /learn-more-about/installing-mobiuscli': '/guides/mobiuscli#installing-mobiuscli',
  'GET /learn-more-about/mdm-disk-encryption': '/guides/enforce-disk-encryption',
  'GET /learn-more-about/encrypt-linux-device': '/guides/linux-disk-encryption-end-user',
  'GET /contribute-to/policies': 'https://github.com/notawar/mobius/edit/main/docs/01-Using-Mobius/standard-query-library/standard-query-library.yml',
  'GET /learn-more-about/end-user-license-agreement': '/guides/macos-setup-experience#end-user-authentication-and-end-user-license-agreement-eula',
  'GET /learn-more-about/end-user-authentication': '/guides/macos-setup-experience#end-user-authentication-and-end-user-license-agreement-eula',
  'GET /learn-more-about/yaml-setup-experience-software': '/docs/configuration/yaml-files#software',
  'GET /learn-more-about/policy-templates': '/policies',
  'GET /learn-more-about/windows-mdm': '/guides/windows-mdm-setup',
  'GET /learn-more-about/ui-gitops-mode': 'https://github.com/notawar/mobius-gitops/?tab=readme-ov-file#mobius-ui',
  'GET /learn-more-about/certificates-query': '/tables/certificates',
  'GET /learn-more-about/gitops': 'https://github.com/notawar/mobius-gitops/',
  'GET /learn-more-about/connect-idp': '/guides/foreign-vitals-map-idp-users-to-hosts',
  'GET /learn-more-about/troubleshoot-idp-connection': '/guides/foreign-vitals-map-idp-users-to-hosts#verify-connection',
  'GET /learn-more-about/unsigning-configuration-profiles': 'https://mobiusmdm.com/guides/custom-os-settings#enforce-os-settings',
  'GET /learn-more-about/how-to-connect-android-enterprise': '/guides/android-mdm-setup',
  'GET /learn-more-about/custom-scep-configuration-profile': '/guides/connect-end-user-to-wifi-with-certificate#step-2-add-scep-configuration-profile-to-mobius2',
  'GET /learn-more-about/ndes-scep-configuration-profile': '/guides/connect-end-user-to-wifi-with-certificate#step-2-add-scep-configuration-profile-to-mobius',
  'GET /learn-more-about/macos-distribution-packages': 'https://scriptingosx.com/2017/09/on-distribution-packages/',
  'GET /learn-more-about/self-service-software': '/guides/software-self-service',
  'GET /learn-more-about/request-hydrant-certificate': '/docs/rest-api#request-certificate',
  'GET /learn-more-about/yaml-software-setup-experience': '/docs/configuration/yaml-files#self-service-labels-categories-and-setup-experience',

  // Sitemap
  // =============================================================================================================
  // This is for search engines, not humans.  Search engines know to visit mobiusmdm.com/sitemap.xml to download this
  // XML file, which helps search engines know which pages are available on the website.
  'GET /sitemap.xml':            { action: 'download-sitemap' },

  // RSS feeds
  // =============================================================================================================
  'GET /rss/:categoryName': {action: 'download-rss-feed'},

  // Potential future pages
  // =============================================================================================================
  // Things that are not webpages here (in the Sails app) yet, but could be in the future.  For now they are just
  // redirects to somewhere else EXTERNAL to the Sails app.
  'GET /security':               'https://github.com/notawar/mobius/security/policy',
  'GET /logout':                 '/api/v1/account/logout',


  //  ╦ ╦╔═╗╔╗ ╦ ╦╔═╗╔═╗╦╔═╔═╗
  //  ║║║║╣ ╠╩╗╠═╣║ ║║ ║╠╩╗╚═╗
  //  ╚╩╝╚═╝╚═╝╩ ╩╚═╝╚═╝╩ ╩╚═╝
  'POST /api/v1/webhooks/receive-usage-analytics': { action: 'webhooks/receive-usage-analytics', csrf: false },
  '/api/v1/webhooks/github': { action: 'webhooks/receive-from-github', csrf: false },
  'POST /api/v1/webhooks/receive-from-stripe': { action: 'webhooks/receive-from-stripe', csrf: false },
  'POST /api/v1/webhooks/receive-from-zapier': { action: 'webhooks/receive-from-zapier', csrf: false },
  'POST /api/v1/get-est-device-certificate': { action: 'get-est-device-certificate', csrf: false},
  'POST /api/v1/webhooks/receive-from-clay': { action: 'webhooks/receive-from-clay', csrf: false},
  'POST /api/v1/webhooks/receive-from-zoom': { action: 'webhooks/receive-from-zoom', csrf: false},


  //  ╔═╗╔╗╔╔╦╗╦═╗╔═╗╦╔╦╗  ╔═╗╦═╗╔═╗═╗ ╦╦ ╦  ╔═╗╔╗╔╔╦╗╔═╗╔═╗╦╔╗╔╔╦╗╔═╗
  //  ╠═╣║║║ ║║╠╦╝║ ║║ ║║  ╠═╝╠╦╝║ ║╔╩╦╝╚╦╝  ║╣ ║║║ ║║╠═╝║ ║║║║║ ║ ╚═╗
  //  ╩ ╩╝╚╝═╩╝╩╚═╚═╝╩═╩╝  ╩  ╩╚═╚═╝╩ ╚═ ╩   ╚═╝╝╚╝═╩╝╩  ╚═╝╩╝╚╝ ╩ ╚═╝
  'POST /api/android/v1/signupUrls': { action: 'android-proxy/create-android-signup-url', csrf: false},
  'POST /api/android/v1/enterprises': { action: 'android-proxy/create-android-enterprise', csrf: false},
  'POST /api/android/v1/enterprises/:androidEnterpriseId/enrollmentTokens': { action: 'android-proxy/create-android-enrollment-token', csrf: false},
  'PATCH /api/android/v1/enterprises/:androidEnterpriseId/policies/:policyId': { action: 'android-proxy/modify-android-policies', csrf: false},
  'DELETE /api/android/v1/enterprises/:androidEnterpriseId': { action: 'android-proxy/delete-one-android-enterprise', csrf: false},


  //  ╔═╗╔═╗╦  ╔═╗╔╗╔╔╦╗╔═╗╔═╗╦╔╗╔╔╦╗╔═╗
  //  ╠═╣╠═╝║  ║╣ ║║║ ║║╠═╝║ ║║║║║ ║ ╚═╗
  //  ╩ ╩╩  ╩  ╚═╝╝╚╝═╩╝╩  ╚═╝╩╝╚╝ ╩ ╚═╝
  // Note that, in this app, these API endpoints may be accessed using the `Cloud.*()` methods
  // from the Parasails library, or by using those method names as the `action` in <ajax-form>.
  'POST /api/v1/deliver-contact-form-message':        { action: 'deliver-contact-form-message' },
  'POST /api/v1/entrance/send-password-recovery-email': { action: 'entrance/send-password-recovery-email' },
  'POST /api/v1/customers/signup':                     { action: 'entrance/signup' },
  'POST /api/v1/account/update-profile':               { action: 'account/update-profile' },
  'POST /api/v1/account/update-password':              { action: 'account/update-password' },
  'POST /api/v1/account/update-billing-card':          { action: 'account/update-billing-card'},
  'POST /api/v1/customers/login':                      { action: 'entrance/login' },
  '/api/v1/account/logout':                            { action: 'account/logout' },
  'POST /api/v1/customers/create-quote':               { action: 'customers/create-quote' },
  'POST /api/v1/customers/save-billing-info-and-subscribe': { action: 'customers/save-billing-info-and-subscribe' },
  'POST /api/v1/entrance/update-password-and-login':    { action: 'entrance/update-password-and-login' },
  'POST /api/v1/deliver-demo-signup':                   { action: 'deliver-demo-signup' },
  'POST /api/v1/create-or-update-one-newsletter-subscription': { action: 'create-or-update-one-newsletter-subscription' },
  '/api/v1/unsubscribe-from-all-newsletters': { action: 'unsubscribe-from-all-newsletters' },
  'POST /api/v1/admin/build-license-key': { action: 'admin/build-license-key' },
  'POST /api/v1/create-vanta-authorization-request': { action: 'create-vanta-authorization-request'},
  'POST /api/v1/create-external-vanta-authorization-request': { action: 'create-vanta-authorization-request', csrf: false },
  'GET /redirect-vanta-authorization-request': { action: 'redirect-vanta-authorization-request' },
  'POST /api/v1/deliver-mdm-beta-signup':                   { action: 'deliver-mdm-beta-signup' },
  'POST /api/v1/get-human-interpretation-from-osquery-sql': { action: 'get-human-interpretation-from-osquery-sql', csrf: false },
  'POST /api/v1/deliver-apple-csr ': { action: 'deliver-apple-csr', csrf: false},
  'POST /api/v1/deliver-mdm-demo-email':               { action: 'deliver-mdm-demo-email' },
  'POST /api/v1/admin/provision-sandbox-instance-and-deliver-email': { action: 'admin/provision-sandbox-instance-and-deliver-email' },
  'POST /api/v1/deliver-talk-to-us-form-submission': { action: 'deliver-talk-to-us-form-submission' },
  'POST /api/v1/save-questionnaire-progress': { action: 'save-questionnaire-progress' },
  'POST /api/v1/account/update-start-cta-visibility': { action: 'account/update-start-cta-visibility' },
  'POST /api/v1/deliver-deal-registration-submission': { action: 'deliver-deal-registration-submission' },
  '/api/v1/unsubscribe-from-marketing-emails': { action: 'unsubscribe-from-marketing-emails' },
  'POST /api/v1/customers/get-stripe-checkout-session-url': { action: 'customers/get-stripe-checkout-session-url' },
  '/api/v1/query-generator/get-llm-generated-sql': { action: 'query-generator/get-llm-generated-sql' },
  'POST /api/v1/get-llm-generated-configuration-profile': { action: 'get-llm-generated-configuration-profile', hasSocketFeatures: true },



  //  ╔╦╗╦╔═╗╦═╗╔═╗╔═╗╔═╗╔═╗╔╦╗  ╔═╗╦═╗╔═╗═╗ ╦╦ ╦  ╔═╗╔╗╔╔╦╗╔═╗╔═╗╦╔╗╔╔╦╗╔═╗
  //  ║║║║║  ╠╦╝║ ║╚═╗║ ║╠╣  ║   ╠═╝╠╦╝║ ║╔╩╦╝╚╦╝  ║╣ ║║║ ║║╠═╝║ ║║║║║ ║ ╚═╗
  //  ╩ ╩╩╚═╝╩╚═╚═╝╚═╝╚═╝╚   ╩   ╩  ╩╚═╚═╝╩ ╚═ ╩   ╚═╝╝╚╝═╩╝╩  ╚═╝╩╝╚╝ ╩ ╚═╝
  'POST /api/v1/microsoft-compliance-partner': { action: 'microsoft-proxy/create-compliance-partner-tenant', csrf: false },
  'GET /api/v1/microsoft-compliance-partner/settings': { action: 'microsoft-proxy/get-compliance-partner-settings' },
  'DELETE /api/v1/microsoft-compliance-partner': { action: 'microsoft-proxy/remove-one-compliance-partner-tenant', csrf: false },
  'POST /api/v1/microsoft-compliance-partner/device': { action: 'microsoft-proxy/update-one-devices-compliance-status', csrf: false },
  'GET /api/v1/microsoft-compliance-partner/device/message': { action: 'microsoft-proxy/get-one-compliance-status-result', },
  'GET /api/v1/microsoft-compliance-partner/adminconsent': { action: 'microsoft-proxy/receive-redirect-from-microsoft', },

  // Well known resources https://datatracker.ietf.org/doc/html/rfc8615
  // =============================================================================================================
  // Temporary enroll endpoint for https://github.com/notawar/mobius/issues/27391
  'GET /.well-known/com.apple.remotemanagement': (req, res)=>{ return res.json({'Servers':[{'Version':'mdm-byod', 'BaseURL':'https://getvictor.ngrok.io/api/mdm/apple/enroll?token=bozo'}]});},
};
