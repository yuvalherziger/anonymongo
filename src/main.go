package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func main() {
	var replacement string
	var anonymizeNumbers bool
	var anonymizeBooleans bool
	var anonymizeIPs bool
	var outputFile string

	var rootCmd = &cobra.Command{
		Use:   "anonymongo <JSON file or gzipped MongoDB log file>",
		Short: "Anonymize MongoDB log files",
		Long:  `Anonymize MongoDB log files by replacing sensitive information with generic placeholders`,
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			logFilePath := args[0]
			SetAnonymizedString(replacement)
			SetAnonymizeNumbers(anonymizeNumbers)
			SetAnonymizeIPs(anonymizeIPs)
			SetAnonymizeBooleans(true)

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

	rootCmd.Flags().StringVarP(&replacement, "replacement", "r", "REDACTED", "Replacement string for anonymized values")
	rootCmd.Flags().BoolVarP(&anonymizeNumbers, "anonymizeNumbers", "n", false, "Anonymize numeric values to 0")
	rootCmd.Flags().BoolVarP(&anonymizeBooleans, "anonymizeBooleans", "b", false, "Anonymize boolean values to false")
	rootCmd.Flags().BoolVarP(&anonymizeIPs, "anonymizeIPs", "i", false, "Anonymize IP addresses to 255.255.255.255")
	rootCmd.Flags().StringVarP(&outputFile, "outputFile", "o", "", "Write output to file instead of stdout")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
