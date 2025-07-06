package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

var version = "dev" // override at build: go build -ldflags "-X main.version=1.2.3"

func main() {
	// Flag for the "redact" command
	var (
		replacement         string
		redactNumbers       bool
		redactBooleans      bool
		redactIPs           bool
		encrypt             bool
		outputFile          string
		eagerRedactionPaths []string
		atlasProjectId      string
		atlasClusterName    string
		atlasPublicKey      string
		atlasPrivateKey     string
		atlasLogStartDate   int
		atlasLogEndDate     int
		encryptionKeyFile   string
	)
	// Flag for the "decrypt" command
	var (
		decryptionKeyFile string
	)

	var rootCmd = &cobra.Command{
		Use:   "anonymongo",
		Short: "A tool for redacting and managing MongoDB log files",
		Long: `anonymongo is a CLI tool designed to redact sensitive information from MongoDB log files,
making them safe to share. It also provides utilities for related tasks.`,
		// No 'Run' function, so it will show help if called without a subcommand.
	}

	var redactCmd = &cobra.Command{
		Use:   "redact [JSON file or gzipped MongoDB log file]",
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

			// Atlas-related parameter detection
			atlasParamsSet := atlasProjectId != "" || atlasClusterName != "" || atlasLogStartDate != 0 || atlasLogEndDate != 0 || atlasPublicKey != "" || atlasPrivateKey != ""

			// Validation: atlasLogStartDate and atlasLogEndDate must be both set or both unset
			if (atlasLogStartDate != 0 && atlasLogEndDate == 0) || (atlasLogStartDate == 0 && atlasLogEndDate != 0) {
				fmt.Fprintln(os.Stderr, "Error: Both --atlasLogStartDate and --atlasLogEndDate must be set together, or neither.")
				os.Exit(1)
			}

			// Validation: atlasProjectId and atlasClusterName must be both set or both unset
			if (atlasProjectId != "" && atlasClusterName == "") || (atlasProjectId == "" && atlasClusterName != "") {
				fmt.Fprintln(os.Stderr, "Error: Both --atlasProjectId and --atlasClusterName must be set together, or neither.")
				os.Exit(1)
			}

			// Validation: Atlas params and positional input are mutually exclusive
			if atlasParamsSet && len(args) == 1 {
				fmt.Fprintln(os.Stderr, "Error: Cannot provide both Atlas parameters and an input file. Please use only one input source.")
				os.Exit(1)
			}
			if atlasParamsSet && stdinHasData {
				fmt.Fprintln(os.Stderr, "Error: Cannot provide both Atlas parameters and piped input. Please use only one input source.")
				os.Exit(1)
			}
			if atlasParamsSet && outputFile == "" {
				fmt.Fprintln(os.Stderr, "Error: When using Atlas parameters, --outputFile (-o) must be specified.")
				os.Exit(1)
			}
			if !atlasParamsSet && len(args) == 1 && stdinHasData {
				fmt.Fprintln(os.Stderr, "Error: Cannot provide both a file and piped input. Please provide only one source.")
				os.Exit(1)
			}
			if encrypt && (stdinHasData || outputFile == "") && !atlasParamsSet {
				fmt.Fprintln(os.Stderr, "Error: --encrypt cannot be used with stdin or stdout. Please specify input and output files when using encryption.")
				os.Exit(1)
			}
			if len(args) == 1 {
				inputFile = args[0]
			} else if stdinHasData {
				useStdin = true
			} else if !atlasParamsSet {
				fmt.Fprintln(os.Stderr, "Error: No input provided. Please specify a file, pipe data to stdin, or use Atlas parameters.")
				os.Exit(1)
			}

			SetRedactedString(replacement)
			SetRedactNumbers(redactNumbers)
			SetRedactIPs(redactIPs)
			SetRedactBooleans(redactBooleans)
			SetEagerRedactionPaths(eagerRedactionPaths)
			SetAtlasLogStartDate(atlasLogStartDate)
			SetAtlasLogEndDate(atlasLogEndDate)

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

			if encrypt && encryptionKeyFile != "" {
				SetShouldEncrypt(encrypt)
				keyfileExists := FileExists(encryptionKeyFile)
				if !keyfileExists {
					newKey, err := GenerateKey()
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error generating encryption key: %v\n", err)
						os.Exit(1)
					}
					err = WriteKeyToFile(encryptionKeyFile, newKey)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error writing encryption key to file: %v\n", err)
						os.Exit(1)
					}
					SetEncryptionKey(newKey)
				} else {
					key, err := ReadKeyFromFile(encryptionKeyFile)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error reading encryption key file: %v\n", err)
						os.Exit(1)
					}
					SetEncryptionKey(key)
				}
			}

			// --- Atlas mode ---
			if atlasParamsSet {
				publicKey := atlasPublicKey
				privateKey := atlasPrivateKey
				if publicKey == "" {
					publicKey = os.Getenv("ATLAS_PUBLIC_KEY")
				}
				if privateKey == "" {
					privateKey = os.Getenv("ATLAS_PRIVATE_KEY")
				}
				if publicKey == "" || privateKey == "" {
					fmt.Fprintln(os.Stderr, "Error: Atlas public/private key not set. Please provide --atlasPublicKey and --atlasPrivateKey or set ATLAS_PUBLIC_KEY and ATLAS_PRIVATE_KEY environment variables.")
					os.Exit(1)
				}
				client := NewAtlasClient(nil)
				start, end := GetStartAndEndDates()
				files, err := client.DownloadClusterLogs(cmd.Context(), publicKey, privateKey, atlasProjectId, atlasClusterName, start, end)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error downloading Atlas logs: %v\n", err)
					os.Exit(1)
				}
				// Always clean up downloaded log files, even if redaction fails
				defer func() {
					if delErr := client.DeleteClusterLogs(cmd.Context(), files); delErr != nil {
						fmt.Fprintf(os.Stderr, "Error cleaning up Atlas log files: %v\n", delErr)
					}
				}()
				fileReader := &DefaultFileReader{}
				for i, file := range files {
					// Compose output file path with serial integer
					outPath := fmt.Sprintf("%s.%d", outputFile, i)
					outWriter, err := os.Create(outPath)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error opening output file %s: %v\n", outPath, err)
						os.Exit(1)
					}
					defer outWriter.Close()
					// Progress bar logic per file
					var bar *progressbar.ProgressBar
					totalLines, err := countLines(fileReader, file)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error counting lines in %s: %v\n", file, err)
						os.Exit(1)
					}
					bar = progressbar.NewOptions64(int64(totalLines),
						progressbar.OptionEnableColorCodes(true),
						progressbar.OptionSetWidth(50),
						progressbar.OptionSetDescription("Redacting..."),
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
						progressbar.OptionShowIts(),
						progressbar.OptionSetItsString("entries"),
						progressbar.OptionShowElapsedTimeOnFinish(),
						progressbar.OptionOnCompletion(func() {
							fmt.Fprintln(os.Stdout, "\n\nRedaction complete - finalizing output...")
						}),
						progressbar.OptionSetWriter(os.Stdout),
						progressbar.OptionThrottle(250*time.Millisecond),
					)
					if err := ProcessMongoLogFile(fileReader, file, outWriter, bar); err != nil {
						fmt.Fprintf(os.Stderr, "Error processing log file %s: %v\n", file, err)
						outWriter.Close()
						os.Exit(1)
					}
					outWriter.Close()
				}
				return
			}

			// --- Non-Atlas mode ---
			if useStdin {
				if err := ProcessMongoLogFileFromReader(os.Stdin, outWriter, nil); err != nil {
					fmt.Fprintf(os.Stderr, "Error processing stdin: %v\n", err)
					os.Exit(1)
				}
			} else {
				fileReader := &DefaultFileReader{}
				var bar *progressbar.ProgressBar
				if outputFile != "" {
					totalLines, err := countLines(fileReader, inputFile)
					if err != nil {
						fmt.Fprintf(os.Stderr, "Error counting lines: %v\n", err)
						os.Exit(1)
					}
					bar = progressbar.NewOptions64(int64(totalLines),
						progressbar.OptionEnableColorCodes(true),
						progressbar.OptionSetWidth(50),
						progressbar.OptionSetDescription("Redacting MongoDB logs..."),
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
						progressbar.OptionShowIts(),
						progressbar.OptionSetItsString("entries"),
						progressbar.OptionShowElapsedTimeOnFinish(),
						progressbar.OptionOnCompletion(func() {
							fmt.Fprintln(os.Stdout, "\n\nRedaction complete - finalizing output...")
						}),
						progressbar.OptionSetWriter(os.Stdout),
						progressbar.OptionThrottle(250*time.Millisecond),
					)
				}
				if err := ProcessMongoLogFile(fileReader, inputFile, outWriter, bar); err != nil {
					fmt.Fprintf(os.Stderr, "Error processing log file: %v\n", err)
					os.Exit(1)
				}
			}
		},
	}

	var decryptCmd = &cobra.Command{
		Use:   "decrypt <value>",
		Short: "Decrypt a value using the provided key file",
		Long:  `Decrypt a single ciphertext string that was previously redacted by anonymongo using a specific encryption key.`,
		Args:  cobra.ExactArgs(1), // Enforces exactly one positional argument.
		Run: func(cmd *cobra.Command, args []string) {
			valueToDecrypt := args[0]

			fmt.Printf("Attempting to decrypt value: %q\n", valueToDecrypt)
			fmt.Printf("Using encryption key file: %s\n", decryptionKeyFile)

			key, err := ReadKeyFromFile(decryptionKeyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading key file: %v\n", err)
				os.Exit(1)
			}
			decodedBytes, err := base64.StdEncoding.DecodeString(valueToDecrypt)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error decoding base64 value: %v\n", err)
				os.Exit(1)
			}

			decryptedValue, err := Decrypt(decodedBytes, key)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Decryption failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Raw value: " + string(decryptedValue))
		},
	}

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("anonymongo version", version)
		},
	}

	// Add subcommands to the root command
	rootCmd.AddCommand(redactCmd)
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(versionCmd)

	// Bind flags to the "redact" subcommand
	redactCmd.Flags().StringVarP(&replacement, "replacement", "r", "REDACTED", "Replacement string for redacted values")
	redactCmd.Flags().StringVarP(&encryptionKeyFile, "encryptionKeyFile", "q", "./anonymongo.enc.key", "Path to the AES256 encryption key file (used only with --encrypt)")
	redactCmd.Flags().BoolVarP(&redactNumbers, "redactNumbers", "n", false, "Redact numeric values to 0")
	redactCmd.Flags().BoolVarP(&redactBooleans, "redactBooleans", "b", false, "Redact boolean values to false")
	redactCmd.Flags().BoolVarP(&encrypt, "encrypt", "y", false, "Encrypt values with deterministic encryption")
	redactCmd.Flags().BoolVarP(&redactIPs, "redactIPs", "i", false, "Redact network locations to 255.255.255.255:65535")
	redactCmd.Flags().StringVarP(&outputFile, "outputFile", "o", "", "Write output to file instead of stdout")
	redactCmd.Flags().StringArrayVarP(&eagerRedactionPaths, "redact-field-names", "z", nil, `[EXPERIMENTAL] Specify namespaces whose field names should be redacted in
addition to their values. The structure is either a namespace; e.g., 'dbName.collName'`)
	redactCmd.Flags().StringVarP(&atlasProjectId, "atlasProjectId", "p", "", "Atlas Project ID, if reading logs from an Atlas cluster")
	redactCmd.Flags().StringVarP(&atlasClusterName, "atlasClusterName", "c", "", "Atlas cluster name, if reading logs from an Atlas cluster")
	redactCmd.Flags().StringVarP(&atlasPublicKey, "atlasPublicKey", "", "", `Atlas API public key, if reading logs from an Atlas cluster
(Environment variable ATLAS_PUBLIC_KEY)`)
	redactCmd.Flags().StringVarP(&atlasPrivateKey, "atlasPrivateKey", "", "", `Atlas API private key, if reading logs from an Atlas cluster
(Environment variable ATLAS_PRIVATE_KEY)`)
	redactCmd.Flags().IntVarP(&atlasLogStartDate, "atlasLogStartDate", "s", 0, `Atlas log start date in epoch seconds, if reading logs from an Atlas cluster.
Extract the last 7 days if not provided`)
	redactCmd.Flags().IntVarP(&atlasLogEndDate, "atlasLogEndDate", "e", 0, `Atlas log end date in epoch seconds, if reading logs from an Atlas cluster.
Extract the last 7 days if not provided`)

	// Bind flags to the "decrypt" subcommand
	decryptCmd.Flags().StringVarP(&decryptionKeyFile, "decryptionKeyFile", "", "./anonymongo.enc.key", "Path to the AES256 encryption key file")
	if err := decryptCmd.MarkFlagRequired("decryptionKeyFile"); err != nil {
		// This error should only happen on a programming error (e.g. flag doesn't exist)
		fmt.Fprintf(os.Stderr, "Error marking flag required: %v\n", err)
		os.Exit(1)
	}

	if err := rootCmd.Execute(); err != nil {
		// Cobra already prints the error, so we don't need to double-print it.
		os.Exit(1)
	}
}

// countLines returns the number of lines in a file using a FileReader.
func countLines(fileReader FileReader, filename string) (int, error) {
	f, err := fileReader.Open(filename)
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
