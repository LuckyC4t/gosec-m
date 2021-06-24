package runner

import "github.com/dop251/goja"

type DynamicRuleRunner struct {
	r *goja.Runtime
}

func (runner *DynamicRuleRunner) SetRuntime(r *goja.Runtime) {
	runner.r = r
}

func (runner *DynamicRuleRunner) GetRuntime() *goja.Runtime {
	return runner.r
}
