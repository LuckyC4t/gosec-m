package gosec

import (
	"github.com/dop251/goja"
)

type DynamicRuleRunner struct {
	r *goja.Runtime
}

type GojaRuleResult struct {
	Issue *Issue
	Error string
}

const (
	ErrWrongArgsNumber = "Wrong Number Of Args"
)

func NewRunner() DynamicRuleRunner {
	vm := goja.New()
	return DynamicRuleRunner{r: vm}
}

func (runner DynamicRuleRunner) GetRuntime() *goja.Runtime {

	return runner.r
}

func (runner DynamicRuleRunner) InitRunner() {
	gosecObj := runner.createGosec()
	utilsObj := runner.createUtils()
	zxcvbnObj := runner.creatZXCVBN()
	runtime := runner.GetRuntime()

	runtime.Set("gosec", gosecObj)
	runtime.Set("utils", utilsObj)
	runtime.Set("zxcvbn", zxcvbnObj)
}
