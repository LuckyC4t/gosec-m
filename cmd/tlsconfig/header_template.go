package main

import "text/template"

var generatedHeaderTmpl = template.Must(template.New("generated").Parse(`
package {{.}}

import (
	"go/ast"

	"gosec-m"
)
`))
