package gosec

import (
	"github.com/LuckyC4t/gosec-m"
	"github.com/LuckyC4t/gosec-m/js2gosec/runner"
	"github.com/dop251/goja"
)

func (g GosecModule) NewCallList(call goja.FunctionCall) goja.Value {
	r := g.GetRuntime()

	if len(call.Arguments) != 0 {
		panic(r.ToValue(runner.ErrWrongArgsNumber))
	}

	calls := gosec.NewCallList()
	return r.ToValue(calls)
}
