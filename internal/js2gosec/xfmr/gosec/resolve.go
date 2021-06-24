package gosec

import (
	"github.com/LuckyC4t/gosec-m"
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/errors"
	"github.com/dop251/goja"
	"go/ast"
)

func (g GosecModule) tryResolve(call goja.FunctionCall) goja.Value {
	r := g.GetRuntime()
	if len(call.Arguments) != 2 {
		panic(r.ToValue(errors.ErrWrongArgsNumber))
	}

	n := call.Argument(0).Export().(ast.Node)
	c := call.Argument(1).Export().(*gosec.Context)

	res := gosec.TryResolve(n, c)
	return r.ToValue(res)
}
