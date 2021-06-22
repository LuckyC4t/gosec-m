package rules

import (
	"go/ast"
	"gosec-m"
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
