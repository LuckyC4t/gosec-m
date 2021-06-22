package yaml

import (
	"io"

	"gopkg.in/yaml.v2"
	"gosec-m"
)

// WriteReport write a report in yaml format to the output writer
func WriteReport(w io.Writer, data *gosec.ReportInfo) error {
	raw, err := yaml.Marshal(data)
	if err != nil {
		return err
	}
	_, err = w.Write(raw)
	return err
}
