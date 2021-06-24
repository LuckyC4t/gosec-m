package gosec

import (
	"github.com/LuckyC4t/gosec-m"
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/errors"
	"github.com/dop251/goja"
)

func (g GosecModule) newCallList(call goja.FunctionCall) goja.Value {
	r := g.GetRuntime()

	if len(call.Arguments) != 0 {
		panic(r.ToValue(errors.ErrWrongArgsNumber))
	}

	calls := gosec.NewCallList()
	return r.ToValue(calls)
}
