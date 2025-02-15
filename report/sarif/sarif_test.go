package sarif_test

import (
	"bytes"

	"github.com/LuckyC4t/gosec-m"
	"github.com/LuckyC4t/gosec-m/report/sarif"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Sarif Formatter", func() {
	BeforeEach(func() {
	})
	Context("when converting to Sarif issues", func() {
		It("sarif formatted report should contain the result", func() {
			buf := new(bytes.Buffer)
			reportInfo := gosec.NewReportInfo([]*gosec.Issue{}, &gosec.Metrics{}, map[string][]gosec.Error{}).WithVersion("v2.7.0")
			err := sarif.WriteReport(buf, reportInfo, []string{})
			result := buf.String()
			Expect(err).ShouldNot(HaveOccurred())
			Expect(result).To(ContainSubstring("\"results\": ["))
		})
	})
})
