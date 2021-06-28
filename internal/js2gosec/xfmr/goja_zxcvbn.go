package xfmr

import (
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/runner"
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/xfmr/zxcvbn"
	"github.com/dop251/goja"
	"log"
)

func CreatZXCVBN(ruleRunner *runner.DynamicRuleRunner) *goja.Object {
	vm := ruleRunner.GetRuntime()
	zxcObj := vm.NewObject()

	z := zxcvbn.ZxcvbnModule{ruleRunner}

	for name, val := range z.Export() {
		if err := zxcObj.Set(name, val); err != nil {
			log.Fatal(err)
		}
	}

	return zxcObj
}
