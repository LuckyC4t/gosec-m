package gosec

import (
	"github.com/dop251/goja"
)

func (g gosecModule) NewCallList(call goja.FunctionCall) goja.Value {
	r := g.GetRuntime()

	if len(call.Arguments) != 0 {
		panic(r.ToValue(ErrWrongArgsNumber))
	}

	calls := NewCallList()
	return r.ToValue(calls)
}
