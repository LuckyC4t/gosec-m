package sarif

import (
	"encoding/json"
	"io"

	"github.com/LuckyC4t/gosec-m"
)

// WriteReport write a report in SARIF format to the output writer
func WriteReport(w io.Writer, data *gosec.ReportInfo, rootPaths []string) error {
	sr, err := GenerateReport(rootPaths, data)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(sr, "", "\t")
	if err != nil {
		return err
	}

	_, err = w.Write(raw)
	return err
}
