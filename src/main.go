package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var version = "dev" // override at build: go build -ldflags "-X main.version=1.2.3"

func main() {
	var replacement string
	var redactNumbers bool
	var redactBooleans bool
	var redactIPs bool
	var outputFile string
	var eagerRedactionPaths []string

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
			SetEagerRedactionPaths(eagerRedactionPaths)

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

			// Progress bar logic
			var bar *progressbar.ProgressBar
			if inputFile != "" && outputFile != "" {
				// Only count lines if both input and output files are provided
				totalLines, err := countLines(inputFile)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error counting lines: %v\n", err)
					os.Exit(1)
				}
				// bar = progressbar.Default(int64(totalLines))
				bar = progressbar.NewOptions64(int64(totalLines),
					progressbar.OptionEnableColorCodes(true),
					progressbar.OptionSetWidth(50),
					progressbar.OptionSetDescription("Redacting MongoDB logs "),
					progressbar.OptionSetTheme(progressbar.Theme{
						Saucer:        "[green]=[reset]",
						SaucerHead:    "[green]>[reset]",
						SaucerPadding: " ",
						BarStart:      "[",
						BarEnd:        "]",
					}),
					progressbar.OptionSetRenderBlankState(true),
					progressbar.OptionSetPredictTime(false),
					progressbar.OptionShowCount(),
					progressbar.OptionOnCompletion(func() { fmt.Fprintln(os.Stdout) }),
					progressbar.OptionSetWriter(os.Stdout),
					progressbar.OptionThrottle(250*time.Millisecond),
				)
			}

			if useStdin {
				if err := ProcessMongoLogFileFromReader(os.Stdin, outWriter, nil); err != nil {
					fmt.Fprintf(os.Stderr, "Error processing stdin: %v\n", err)
					os.Exit(1)
				}
			} else {
				if err := ProcessMongoLogFile(inputFile, outWriter, bar); err != nil {
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
	rootCmd.Flags().BoolVarP(&redactIPs, "redactIPs", "i", false, "Redact network locations to 255.255.255.255:65535")
	rootCmd.Flags().StringVarP(&outputFile, "outputFile", "o", "", "Write output to file instead of stdout")
	rootCmd.Flags().StringArrayVarP(&eagerRedactionPaths, "redact-field-names", "z", nil, `[EXPERIMENTAL] Specify namespaces whose field names should be redacted in
addition to their values. The structure is either a namespace; e.g., 'dbName.collName'`)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// countLines returns the number of lines in a file.
func countLines(filename string) (int, error) {
	f, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := f.Read(buf)
		count += countOccurrences(buf[:c], lineSep)
		switch {
		case err == nil:
		case err == io.EOF:
			return count, nil
		default:
			return count, err
		}
	}
}

func countOccurrences(b, sep []byte) int {
	count := 0
	idx := 0
	for {
		i := indexOf(b[idx:], sep)
		if i == -1 {
			break
		}
		count++
		idx += i + len(sep)
	}
	return count
}

func indexOf(b, sep []byte) int {
	for i := 0; i+len(sep) <= len(b); i++ {
		match := true
		for j := range sep {
			if b[i+j] != sep[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
