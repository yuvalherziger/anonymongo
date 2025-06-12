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
		Use:   "anonymongo [JSON file or gzipped MongoDB log file]",
		Short: "Redact MongoDB log files",
		Long: `Redact MongoDB log files by replacing sensitive information with generic placeholders.

You can provide input either as a file (as the first argument) or by piping logs to stdin.`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var inputFile string
			var useStdin bool

			// Check if stdin is being piped
			stat, _ := os.Stdin.Stat()
			stdinHasData := (stat.Mode() & os.ModeCharDevice) == 0

			if len(args) == 1 && stdinHasData {
				fmt.Fprintln(os.Stderr, "Error: Cannot provide both a file and piped input. Please provide only one source.")
				os.Exit(1)
			}

			if len(args) == 1 {
				inputFile = args[0]
			} else if stdinHasData {
				useStdin = true
			} else {
				fmt.Fprintln(os.Stderr, "Error: No input provided. Please specify a file or pipe data to stdin.")
				os.Exit(1)
			}

			SetRedactedString(replacement)
			SetRedactNumbers(redactNumbers)
			SetRedactIPs(redactIPs)
			SetRedactBooleans(redactBooleans)

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

			if useStdin {
				if err := ProcessMongoLogFileFromReader(os.Stdin, outWriter); err != nil {
					fmt.Fprintf(os.Stderr, "Error processing stdin: %v\n", err)
					os.Exit(1)
				}
			} else {
				if err := ProcessMongoLogFile(inputFile, outWriter); err != nil {
					fmt.Fprintf(os.Stderr, "Error processing log file: %v\n", err)
					os.Exit(1)
				}
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
