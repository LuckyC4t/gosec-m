package gosec

import (
	"github.com/LuckyC4t/gosec-m"
	"github.com/LuckyC4t/gosec-m/internal/js2gosec/errors"
	"github.com/dop251/goja"
	"go/ast"
)

func (g GosecModule) newMetaData(call goja.FunctionCall) goja.Value {
	r := g.GetRuntime()

	if len(call.Arguments) != 0 {
		panic(r.ToValue(errors.ErrWrongArgsNumber))
	}

	value := new(gosec.MetaData)
	return r.ToValue(value)
}

func (g GosecModule) newIssue(call goja.FunctionCall) goja.Value {
	r := g.GetRuntime()

	if len(call.Arguments) != 6 {
		panic(r.ToValue(errors.ErrWrongArgsNumber))
	}

	c := call.Argument(0).Export().(*gosec.Context)
	n := call.Argument(1).Export().(ast.Node)
	id := call.Argument(2).String()
	what := call.Argument(3).String()
	severity := call.Argument(4).Export().(gosec.Score)
	confidence := call.Argument(5).Export().(gosec.Score)

	value := gosec.NewIssue(c, n, id, what, severity, confidence)
	return r.ToValue(value)
}
