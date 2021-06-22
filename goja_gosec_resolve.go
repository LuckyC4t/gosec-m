package gosec

import (
	"github.com/dop251/goja"
	"go/ast"
)

func (g gosecModule) TryResolve(call goja.FunctionCall) goja.Value {
	r := g.GetRuntime()
	if len(call.Arguments) != 2 {
		panic(r.ToValue(ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(ast.Node)
	c := call.Argument(1).Export().(*Context)

	res := TryResolve(n, c)
	return r.ToValue(res)
}
