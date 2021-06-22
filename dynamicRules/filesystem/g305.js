let metaData = gosec.NewMetaData()
metaData.ID = "G305"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.High
metaData.What = "File traversal when extracting zip/tar archive"

let calls = gosec.NewCallList()
calls.Add("path/filepath", "Join")
calls.Add("path", "Join")

let rule = {
    "metaData": metaData,
    "calls": calls,
    "argTypes": ["*archive/zip.File", "*archive/tar.Header"],
    "for": ["*ast.CallExpr"]
}

function match(n, c) {
    let node = rule.calls.ContainsPkgCallExpr(n, c, false)
    if (node !== null) { // != undefined
        let args = node.Args
        let argType = undefined
        for (let arg of node.Args) {
            if (utils.isType(arg, "*ast.SelectorExpr")) {
                let selector = utils.transformTo(arg, "*ast.SelectorExpr")
                argType = c.Info.TypeOf(selector.X)
            } else if (utils.isType(arg, "*ast.Ident")) {
                let ident = utils.transformTo(arg, "*ast.Ident")
                if (ident !== null && ident.Obj.Kind.String() === "var") {
                    let decl = ident.Obj.Decl
                    let assign = utils.transformTo(decl, "*ast.AssignStmt")
                    if (assign !== null) {
                        let selector = utils.transformTo(assign.Rhs[0], "*ast.SelectorExpr")
                        if (selector !== null) {
                            argType = c.Info.TypeOf(selector.X)
                        }
                    }
                }
            }

            if (argType !== undefined) {
                for (let t of rule.argTypes) {
                    if (argType.String() === t) {
                        let issue = gosec.NewIssue(c, n,
                            rule.metaData.ID, rule.metaData.What, rule.metaData.Severity, rule.metaData.Confidence)
                        return {
                            "Issue": issue,
                            "Error": null
                        }
                    }
                }
            }
        }
    }

    return {
        "Issue": null,
        "Error": null
    }
}