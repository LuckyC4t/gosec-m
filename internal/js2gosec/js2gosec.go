package js2gosec

import (
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/runner"
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/xfmr"
	"github.com/dop251/goja"
)

func NewRunner() *runner.DynamicRuleRunner {
	vm := goja.New()
	ruleRunner := new(runner.DynamicRuleRunner)
	ruleRunner.SetRuntime(vm)
	return ruleRunner
}

func InitRunner(ruleRunner *runner.DynamicRuleRunner) {
	gosecObj := xfmr.CreateGosec(ruleRunner)
	utilsObj := xfmr.CreateUtils(ruleRunner)
	zxcvbnObj := xfmr.CreatZXCVBN(ruleRunner)

	runtime := ruleRunner.GetRuntime()

	runtime.Set("gosec", gosecObj)
	runtime.Set("utils", utilsObj)
	runtime.Set("zxcvbn", zxcvbnObj)
}
