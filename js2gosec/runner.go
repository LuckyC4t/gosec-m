package js2gosec

import (
	"github.com/dop251/goja"
	"gosec-m"
	"gosec-m/js2gosec/pkg"
	"gosec-m/js2gosec/runner"
)

type GojaRuleResult struct {
	Issue *gosec.Issue
	Error string
}

func NewRunner() *runner.DynamicRuleRunner {
	vm := goja.New()
	ruleRunner := new(runner.DynamicRuleRunner)
	ruleRunner.SetRuntime(vm)
	return ruleRunner
}

func InitRunner(ruleRunner *runner.DynamicRuleRunner) {
	gosecObj := pkg.CreateGosec(ruleRunner)
	utilsObj := pkg.CreateUtils(ruleRunner)
	zxcvbnObj := pkg.CreatZXCVBN(ruleRunner)

	runtime := ruleRunner.GetRuntime()

	runtime.Set("gosec", gosecObj)
	runtime.Set("utils", utilsObj)
	runtime.Set("zxcvbn", zxcvbnObj)
}
