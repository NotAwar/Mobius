parasails.registerPage('mobiuscli-preview', {
  //  ╦╔╗╔╦╔╦╗╦╔═╗╦    ╔═╗╔╦╗╔═╗╔╦╗╔═╗
  //  ║║║║║ ║ ║╠═╣║    ╚═╗ ║ ╠═╣ ║ ║╣
  //  ╩╝╚╝╩ ╩ ╩╩ ╩╩═╝  ╚═╝ ╩ ╩ ╩ ╩ ╚═╝
  data: {
    selectedPlatform: 'macos',
    installCommands: {
      macos: 'curl -sSL https://mobiusmdm.com/resources/install-mobiuscli.sh | bash',
      linux: 'curl -sSL https://mobiusmdm.com/resources/install-mobiuscli.sh | bash',
      windows: `for /f "tokens=1,* delims=:" %a in ('curl -s https://api.github.com/repos/mobiusmdm/mobius/releases/latest ^| findstr "browser_download_url" ^| findstr "_windows_amd64.zip"') do (curl -kOL %b) && if not exist "%USERPROFILE%\\.mobiuscli" mkdir "%USERPROFILE%\\.mobiuscli" && for /f "delims=" %a in ('dir /b mobiuscli_*_windows_amd64.zip') do tar -xf "%a" --strip-components=1 -C "%USERPROFILE%\\.mobiuscli" && del "%a"`,
      npm: 'npm install mobiuscli -g',
    },
    mobiuscliPreviewTerminalCommand: {
      macos: '~/.mobiuscli/mobiuscli preview',
      linux: '~/.mobiuscli/mobiuscli preview',
      windows: `%USERPROFILE%\\.mobiuscli\\mobiuscli preview`,
      npm: 'mobiuscli preview',
    },
    // For conditionally rendering messages based on if the user is logged in or not.
    me: undefined,

  },

  //  ╦  ╦╔═╗╔═╗╔═╗╦ ╦╔═╗╦  ╔═╗
  //  ║  ║╠╣ ║╣ ║  ╚╦╝║  ║  ║╣
  //  ╩═╝╩╚  ╚═╝╚═╝ ╩ ╚═╝╩═╝╚═╝
  beforeMount: function() {
    //…
  },
  mounted: async function() {
    //…
  },

  //  ╦╔╗╔╔╦╗╔═╗╦═╗╔═╗╔═╗╔╦╗╦╔═╗╔╗╔╔═╗
  //  ║║║║ ║ ║╣ ╠╦╝╠═╣║   ║ ║║ ║║║║╚═╗
  //  ╩╝╚╝ ╩ ╚═╝╩╚═╩ ╩╚═╝ ╩ ╩╚═╝╝╚╝╚═╝
  methods: {
    clickCopyInstallCommand: async function(platform) {
      let commandToInstallMobiusctl = this.installCommands[platform];
      // https://caniuse.com/mdn-api_clipboard_writetext
      $('[purpose="install-copy-button"]').addClass('copied');
      await setTimeout(()=>{
        $('[purpose="install-copy-button"]').removeClass('copied');
      }, 2000);
      navigator.clipboard.writeText(commandToInstallMobiusctl);
    },

    clickCopyTerminalCommand: async function(platform) {
      let commandToRunMobiusPreview = this.mobiuscliPreviewTerminalCommand[platform];
      if(this.trialLicenseKey && !this.userHasExpiredTrialLicense){
        commandToRunMobiusPreview += ' --license-key '+this.trialLicenseKey;
      }
      $('[purpose="command-copy-button"]').addClass('copied');
      await setTimeout(()=>{
        $('[purpose="command-copy-button"]').removeClass('copied');
      }, 2000);
      // https://caniuse.com/mdn-api_clipboard_writetext
      navigator.clipboard.writeText(commandToRunMobiusPreview);
    },
  }
});
