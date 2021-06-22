let metaData = gosec.NewMetaData()
metaData.ID = "G203"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.Low
metaData.What = "this method will not auto-escape HTML. Verify data is well formed."

let calls = gosec.NewCallList()
calls.Add("html/template", "HTML")
calls.Add("html/template", "HTMLAttr")
calls.Add("html/template", "JS")
calls.Add("html/template", "URL")

let rule = {
    "metaData": metaData,
    "calls": calls,
    "for": ["*ast.CallExpr"]
}

function match(n, c) {
    let node = rule.calls.ContainsPkgCallExpr(n, c, false)
    if (node !== null) {
        for (let arg of node.Args) {
            if (!utils.isType(arg, "*ast.BasicLit")) {
                return {
                    "Issue": gosec.NewIssue(c, n,
                        rule.metaData.ID, rule.metaData.What,
                        rule.metaData.Severity, rule.metaData.Confidence),
                    "Error": null
                }
            }
        }
    }
    return {"Issue": null, "Error": null}
}