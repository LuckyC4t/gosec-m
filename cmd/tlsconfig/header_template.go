package main

import "text/template"

var generatedHeaderTmpl = template.Must(template.New("generated").Parse(`
package {{.}}

import (
	"go/ast"

	"github.com/LuckyC4t/gosec-m"
)
`))
