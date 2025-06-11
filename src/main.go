package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version = "dev" // override at build: go build -ldflags "-X main.version=1.2.3"

func main() {
	var replacement string
	var redactNumbers bool
	var redactBooleans bool
	var redactIPs bool
	var outputFile string

	var rootCmd = &cobra.Command{
		Use:   "anonymongo <JSON file or gzipped MongoDB log file>",
		Short: "Redact MongoDB log files",
		Long:  `Redact MongoDB log files by replacing sensitive information with generic placeholders`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			logFilePath := args[0]
			SetRedactedString(replacement)
			SetRedactNumbers(redactNumbers)
			SetRedactIPs(redactIPs)
			SetRedactBooleans(true)

			var outWriter *os.File
			var err error
			if outputFile != "" {
				outWriter, err = os.Create(outputFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
					os.Exit(1)
				}
				defer outWriter.Close()
			} else {
				outWriter = os.Stdout
			}

			if err := ProcessMongoLogFile(logFilePath, outWriter); err != nil {
				fmt.Fprintf(os.Stderr, "Error processing log file: %v\n", err)
				os.Exit(1)
			}
		},
	}

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("anonymongo version", version)
		},
	}

	rootCmd.AddCommand(versionCmd)

	rootCmd.Flags().StringVarP(&replacement, "replacement", "r", "REDACTED", "Replacement string for redacted values")
	rootCmd.Flags().BoolVarP(&redactNumbers, "redactNumbers", "n", false, "Redact numeric values to 0")
	rootCmd.Flags().BoolVarP(&redactBooleans, "redactBooleans", "b", false, "Redact boolean values to false")
	rootCmd.Flags().BoolVarP(&redactIPs, "redactIPs", "i", false, "Redact IP addresses to 255.255.255.255")
	rootCmd.Flags().StringVarP(&outputFile, "outputFile", "o", "", "Write output to file instead of stdout")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
