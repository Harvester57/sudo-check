package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sudo-check/pkg/fleet"

	"github.com/spf13/cobra"
)

var mergeCmd = &cobra.Command{
	Use:   "merge <file-or-dir...>",
	Short: "Aggregate multiple JSON audit reports into a fleet summary",
	Long: `Merge multiple host JSON AuditResult files (or directories containing *.json
audit reports) into consolidated host risk rankings and rule prevalence summaries
in HTML, CSV, and/or JSON formats.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		requestedFormats, err := mergeResolveFormats(cmd)
		if err != nil {
			return err
		}

		if outputDir == "" {
			if slices.Contains(requestedFormats, "html") {
				return fmt.Errorf("report format html requires --output-dir (-o)")
			}
			if len(requestedFormats) > 1 {
				return fmt.Errorf("cannot write multiple formats (%s) to stdout; specify --output-dir (-o) or a single format", strings.Join(requestedFormats, ", "))
			}
		}

		inputFiles, err := mergeCollectInputFiles(args, outputDir)
		if err != nil {
			return err
		}
		if len(inputFiles) == 0 {
			return fmt.Errorf("no JSON report files found in the specified input path(s)")
		}

		summary, err := fleet.MergeReportFiles(inputFiles)
		if err != nil {
			return err
		}

		if outputDir != "" {
			if err := os.MkdirAll(outputDir, 0755); err != nil {
				return fmt.Errorf("failed to create output directory: %w", err)
			}

			generated := make(map[string]string, len(requestedFormats))
			for _, fmtName := range requestedFormats {
				var outPath string
				var writeFn func(*os.File) error
				switch fmtName {
				case "html":
					outPath = filepath.Join(outputDir, "fleet-report.html")
					writeFn = func(f *os.File) error { return fleet.WriteFleetHTML(summary, f) }
				case "csv":
					outPath = filepath.Join(outputDir, "fleet-report.csv")
					writeFn = func(f *os.File) error { return fleet.WriteFleetCSV(summary, f) }
				case "json":
					outPath = filepath.Join(outputDir, "fleet-report.json")
					writeFn = func(f *os.File) error { return fleet.WriteFleetJSON(summary, f) }
				}
				if err := mergeWriteFile(outPath, writeFn); err != nil {
					return fmt.Errorf("failed to write %s fleet report: %w", fmtName, err)
				}
				generated[fmtName] = outPath
			}

			fmt.Fprintf(os.Stderr, "\nFleet merge completed successfully (%d hosts, %d findings)! Generated reports:\n", summary.HostCount, summary.TotalFindings)
			fmtNames := make([]string, 0, len(generated))
			for fmtName := range generated {
				fmtNames = append(fmtNames, fmtName)
			}
			slices.Sort(fmtNames)
			for _, fmtName := range fmtNames {
				fmt.Fprintf(os.Stderr, "  - %s: %s\n", strings.ToUpper(fmtName), generated[fmtName])
			}
			return nil
		}

		out := cmd.OutOrStdout()
		switch requestedFormats[0] {
		case "csv":
			return fleet.WriteFleetCSV(summary, out)
		case "json":
			return fleet.WriteFleetJSON(summary, out)
		default:
			return fmt.Errorf("unsupported stdout merge format %q", requestedFormats[0])
		}
	},
}

func mergeResolveFormats(cmd *cobra.Command) ([]string, error) {
	if !cmd.Flags().Changed("formats") {
		return []string{"html", "csv", "json"}, nil
	}

	raw := getFormatsList()
	if len(raw) == 0 {
		return nil, fmt.Errorf("no output formats specified (supported: html, csv, json)")
	}

	normalized := make([]string, 0, len(raw))
	seen := make(map[string]bool, len(raw))
	for _, r := range raw {
		norm := strings.ToLower(strings.TrimSpace(r))
		switch norm {
		case "html", "csv", "json":
			if !seen[norm] {
				seen[norm] = true
				normalized = append(normalized, norm)
			}
		default:
			return nil, fmt.Errorf("unsupported merge format %q (supported: html, csv, json)", r)
		}
	}
	return normalized, nil
}

func mergeNormalizePathKey(p string) string {
	native := filepath.FromSlash(p)
	if abs, err := filepath.Abs(native); err == nil {
		return filepath.ToSlash(filepath.Clean(abs))
	}
	return filepath.ToSlash(filepath.Clean(native))
}

func mergeCollectInputFiles(args []string, outDir string) ([]string, error) {
	var outDirKey string
	if strings.TrimSpace(outDir) != "" {
		outDirKey = mergeNormalizePathKey(outDir)
	}

	seen := make(map[string]bool)
	var files []string

	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil {
			return nil, fmt.Errorf("input path not found: %w", err)
		}

		if !info.IsDir() {
			key := mergeNormalizePathKey(arg)
			if !seen[key] {
				seen[key] = true
				files = append(files, filepath.Clean(arg))
			}
			continue
		}

		argKey := mergeNormalizePathKey(arg)
		var dirFiles []string
		err = filepath.WalkDir(arg, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				name := d.Name()
				curKey := mergeNormalizePathKey(path)
				if path != arg && strings.HasPrefix(name, ".") {
					return filepath.SkipDir
				}
				if outDirKey != "" && curKey == outDirKey && curKey != argKey {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
				dirFiles = append(dirFiles, filepath.Clean(path))
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("failed to walk directory %s: %w", arg, err)
		}

		slices.Sort(dirFiles)
		for _, df := range dirFiles {
			key := mergeNormalizePathKey(df)
			if !seen[key] {
				seen[key] = true
				files = append(files, df)
			}
		}
	}

	return files, nil
}

func mergeWriteFile(path string, fn func(*os.File) error) (err error) {
	f, createErr := os.Create(path)
	if createErr != nil {
		return fmt.Errorf("failed to create file %s: %w", path, createErr)
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close file %s: %w", path, closeErr)
		}
	}()
	return fn(f)
}

func init() {
	rootCmd.AddCommand(mergeCmd)
}
