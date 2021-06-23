package rules

import (
	"github.com/LuckyC4t/gosec-m"
	"go/ast"
)

type DynamicRule struct {
	id    string
	match func(ast.Node, *gosec.Context) (*gosec.Issue, error)
}

func (d *DynamicRule) ID() string {
	return d.id
}

func (d *DynamicRule) Match(n ast.Node, c *gosec.Context) (*gosec.Issue, error) {
	return d.match(n, c)
}

func (d *DynamicRule) Init(id string, match func(ast.Node, *gosec.Context) (*gosec.Issue, error)) {
	d.id = id
	d.match = match
}
