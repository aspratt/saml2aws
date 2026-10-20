package commands

import "strings"

// ClientSecretOnArgv reports whether the OneLogin client secret was passed as
// a command-line flag, where other local users can read it through ps or /proc.
func ClientSecretOnArgv(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if arg == "--client-secret" || strings.HasPrefix(arg, "--client-secret=") {
			return true
		}
	}
	return false
}
