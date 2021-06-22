package gosec

import (
	"github.com/dop251/goja"
	"go/ast"
)

func (g gosecModule) NewMetaData(call goja.FunctionCall) goja.Value {
	r := g.GetRuntime()

	if len(call.Arguments) != 0 {
		panic(r.ToValue("Wrong Num Args"))
	}

	value := new(MetaData)
	return r.ToValue(value)
}

func (g gosecModule) NewIssue(call goja.FunctionCall) goja.Value {
	r := g.GetRuntime()

	if len(call.Arguments) != 6 {
		panic(r.ToValue("Wrong Num Args"))
	}

	c := call.Argument(0).Export().(*Context)
	n := call.Argument(1).Export().(ast.Node)
	id := call.Argument(2).String()
	what := call.Argument(3).String()
	severity := call.Argument(4).Export().(Score)
	confidence := call.Argument(5).Export().(Score)

	value := NewIssue(c, n, id, what, severity, confidence)
	return r.ToValue(value)
}
