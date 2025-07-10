package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var version = "dev" // override at build: go build -ldflags "-X main.version=1.2.3"

func main() {
	// Prioritize ANONYMONGO_VERSION env var if set
	if v := os.Getenv("ANONYMONGO_VERSION"); v != "" {
		version = v
	}

	// Flag for the "redact" command
	var (
		replacement          string
		redactNumbers        bool
		redactBooleans       bool
		redactIPs            bool
		encrypt              bool
		outputFile           string
		eagerRedactionPaths  []string
		redactedFieldsRegexp string
		atlasProjectId       string
		atlasClusterName     string
		atlasPublicKey       string
		atlasPrivateKey      string
		atlasLogStartDate    int
		atlasLogEndDate      int
		encryptionKeyFile    string
		redactNamespaces     bool
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
		Example: `
	# Redact a file:
	anonymongo redact /path/to/mongodb.log.gz -o redacted.log.gz
	
	# Redact Atlas cluster logs:
	ATLAS_PUBLIC_KEY=<API_PUBLIC_KEY> \
	ATLAS_PRIVATE_KEY=<API_PRIVATE_KEY> \
	anonymongo redact --atlasClusterName <CLUSTER_NAME> \
	  --atlasProjectId <ATLAS_PROJECT_ID> \
	  --outputFile ./mongod.redacted.log

	# Redact only specific fields with a regular expression:
	anonymongo redact --redactFieldRegexp '^(SSN|NHS_ID|phoneNumber)$'
`,
		Run: func(cmd *cobra.Command, args []string) {
			var inputFile string
			var useStdin bool

			// Check if stdin is being piped
			stat, _ := os.Stdin.Stat()
			stdinHasData := (stat.Mode() & os.ModeCharDevice) == 0

			// Atlas-related parameter detection
			atlasParamsSet := atlasProjectId != "" || atlasClusterName != "" || atlasLogStartDate != 0 || atlasLogEndDate != 0 || atlasPublicKey != "" || atlasPrivateKey != ""

			if redactedFieldsRegexp != "" && len(eagerRedactionPaths) > 0 {
				fmt.Fprintln(os.Stderr, "Error: Cannot provide both --redactedFieldsRegexp and --redactFieldNames flags. Please use only one.")
				os.Exit(1)
			}
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
			SetRedactNamespaces(redactNamespaces)
			SetRedactedFieldsRegexp(redactedFieldsRegexp)

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

	var (
		replacementDesc         = "Replacement string for redacted values"
		encryptionKeyFileDesc   = "Path to the AES256 encryption key file (used only with --encrypt)"
		redactNumbersDesc       = "Redact numeric values to 0"
		redactBooleansDesc      = "atlasLogStartDate"
		encryptDesc             = "Encrypt values with deterministic encryption"
		redactIPsDesc           = "Redact network locations to 255.255.255.255:65535"
		outputFileDesc          = "Write output to file instead of stdout"
		eagerRedactionPathsDesc = `[EXPERIMENTAL] Specify namespaces whose field names should be redacted in
addition to their values. The structure is a namespace; e.g., 'dbName.collName'`
		redactedFieldsRegexpDesc = `Specify a regular expression for field names to redact.
PLEASE NOTE: Using this flag will not redact fields that don't match the pattern`
		atlasProjectIdDesc   = "Atlas project ID, if reading logs from an Atlas cluster"
		atlasClusterNameDesc = "Atlas cluster name, if reading logs from an Atlas cluster"
		atlasPublicKeyDesc   = `Atlas API public key, if reading logs from an Atlas cluster
(Environment variable ATLAS_PUBLIC_KEY)`
		atlasPrivateKeyDesc = `Atlas API private key, if reading logs from an Atlas cluster
(Environment variable ATLAS_PRIVATE_KEY)`
		atlasLogStartDateDesc = `Atlas log start date in epoch seconds, if reading logs from an Atlas cluster.
Extract the last 7 days if not provided`
		atlasLogEndDateDesc = `Atlas log end date in epoch seconds, if reading logs from an Atlas cluster.
Extract the last 7 days if not provided`
		redactNamespacesDesc = "Redact database and collection names"
	)
	outputOptions := pflag.NewFlagSet("Output Options", pflag.ExitOnError)
	atlasFlags := pflag.NewFlagSet("Atlas Options", pflag.ExitOnError)
	redactionFlags := pflag.NewFlagSet("Redaction Options", pflag.ExitOnError)
	encryptionFlags := pflag.NewFlagSet("Encryption Options", pflag.ExitOnError)

	flagGroups := map[string]*pflag.FlagSet{
		outputOptions.Name():   outputOptions,
		atlasFlags.Name():      atlasFlags,
		redactionFlags.Name():  redactionFlags,
		encryptionFlags.Name(): encryptionFlags,
	}

	redactCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Println(cmd.Short)

		fmt.Printf("\nUsage:\n  %s\n", cmd.UseLine())

		if cmd.Example != "" {
			fmt.Printf("\nExamples:\n%s\n", cmd.Example)
		}

		// Print flags by group using built-in formatting
		for groupName, fs := range flagGroups {
			fmt.Printf("\n%s:\n", groupName)
			fmt.Print(fs.FlagUsagesWrapped(120))
		}
	})

	// Bind flags to the "redact" subcommand
	redactionFlags.StringVarP(&replacement, "replacement", "r", "REDACTED", replacementDesc)
	encryptionFlags.StringVarP(&encryptionKeyFile, "encryptionKeyFile", "q", "./anonymongo.enc.key", encryptionKeyFileDesc)
	redactionFlags.BoolVarP(&redactNumbers, "redactNumbers", "n", false, redactNumbersDesc)
	redactionFlags.BoolVarP(&redactBooleans, "redactBooleans", "b", false, redactBooleansDesc)
	encryptionFlags.BoolVarP(&encrypt, "encrypt", "y", false, encryptDesc)
	redactionFlags.BoolVarP(&redactIPs, "redactIPs", "i", false, redactIPsDesc)
	outputOptions.StringVarP(&outputFile, "outputFile", "o", "", outputFileDesc)
	redactionFlags.StringArrayVarP(&eagerRedactionPaths, "redactFieldNames", "f", nil, eagerRedactionPathsDesc)
	redactionFlags.StringVarP(&redactedFieldsRegexp, "redactFieldRegexp", "z", "", redactedFieldsRegexpDesc)
	atlasFlags.StringVarP(&atlasProjectId, "atlasProjectId", "p", "", atlasProjectIdDesc)
	atlasFlags.StringVarP(&atlasClusterName, "atlasClusterName", "c", "", atlasClusterNameDesc)
	atlasFlags.StringVarP(&atlasPublicKey, "atlasPublicKey", "", "", atlasPublicKeyDesc)
	atlasFlags.StringVarP(&atlasPrivateKey, "atlasPrivateKey", "", "", atlasPrivateKeyDesc)
	atlasFlags.IntVarP(&atlasLogStartDate, "atlasLogStartDate", "s", 0, atlasLogStartDateDesc)
	atlasFlags.IntVarP(&atlasLogEndDate, "atlasLogEndDate", "e", 0, atlasLogEndDateDesc)
	redactionFlags.BoolVarP(&redactNamespaces, "redactNamespaces", "w", false, redactNamespacesDesc)

	redactCmd.Flags().AddFlagSet(outputOptions)
	redactCmd.Flags().AddFlagSet(atlasFlags)
	redactCmd.Flags().AddFlagSet(redactionFlags)
	redactCmd.Flags().AddFlagSet(encryptionFlags)
	// Bind flags to the "decrypt" subcommand
	decryptCmd.Flags().StringVarP(&decryptionKeyFile, "decryptionKeyFile", "", "./anonymongo.enc.key", "Path to the AES256 encryption key file")

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
