package cli

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
)

var flagAcceptTerms = flag.Bool("acceptTerms", false, "accept ACME provider's terms of service")

func PromptRequireAcceptTerms(termsURI string) {
	if !*flagAcceptTerms {
		fmt.Println()
		fmt.Println("######################################################")
		fmt.Println("The ACME provder you are registering with requires acceptance of these terms of service:")
		fmt.Println(termsURI)

		if isatty.IsTerminal(os.Stdin.Fd()) {
			stdin := bufio.NewReader(os.Stdin)
			for {
				fmt.Print("Do you agree? (Y)es/(N)o: ")
				ans, err := stdin.ReadString('\n')
				if err != nil {
					fmt.Print("Error getting prompt response: ", err)
					os.Exit(2)
				}
				switch strings.ToLower(strings.TrimSpace(ans)) {
				case "y", "yes":
					fmt.Println("######################################################")
					fmt.Println()
					return
				case "n", "no":
					fmt.Print("Terms rejected; exiting...")
					os.Exit(1)
				}
			}
		} else {
			fmt.Println("You can run this command in a supported terminal or pass the -acceptTerms flag.")
			os.Exit(1)
		}
	}
}
