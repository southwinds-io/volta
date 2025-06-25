package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var completionCmd = &cobra.Command{
	Use:   "completion [bash|zsh|fish|powershell]",
	Short: "Generate completion script",
	Long: `To load completions:

Bash:
   $  source <(vault completion bash)

  # To load completions for each session, execute once:
  # Linux:
   $  vault completion bash > /etc/bash_completion.d/vault
  # macOS:
  $ vault completion bash >  $ (brew --prefix)/etc/bash_completion.d/vault

Zsh:
  # If shell completion is not already enabled in your environment,
  # you will need to enable it. You can execute the following once:
   $  echo "autoload -U compinit; compinit" >> ~/.zshrc

  # To load completions for each session, execute once:
  $ vault completion zsh > "${fpath[1]}/_vault"

  # You will need to start a new shell for this setup to take effect.

fish:
   $  vault completion fish | source

  # To load completions for each session, execute once:
   $  vault completion fish > ~/.config/fish/completions/vault.fish

PowerShell:
  PS> vault completion powershell | Out-String | Invoke-Expression

  # To load completions for each session, execute once:
  PS> vault completion powershell > vault.ps1
  PS> . vault.ps1
`,
	DisableFlagsInUseLine: true,
	ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
	Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	Run:                   generateCompletion,
}

func init() {
	rootCmd.AddCommand(completionCmd)
}

func generateCompletion(cmd *cobra.Command, args []string) {
	switch args[0] {
	case "bash":
		cmd.Root().GenBashCompletion(os.Stdout)
	case "zsh":
		cmd.Root().GenZshCompletion(os.Stdout)
	case "fish":
		cmd.Root().GenFishCompletion(os.Stdout, true)
	case "powershell":
		cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
	}
}
