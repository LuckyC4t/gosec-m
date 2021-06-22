let metaData = gosec.NewMetaData()
metaData.ID = "G303"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.High
metaData.What = "File creation in shared tmp directory without using ioutil.Tempfile"

let calls = gosec.NewCallList()
calls.Add("io/ioutil", "WriteFile")
calls.Add("os", "Create")

let rule = {
    "metaData": metaData,
    "calls": calls,
    "args": new RegExp("^/tmp/.*$|^/var/tmp/.*$"),
    "for": ["*ast.CallExpr"]
}

function match(n, c) {
    let node = rule.calls.ContainsPkgCallExpr(n, c, false)
    if (node !== null) {
        try {
            let arg = gosec.GetString(node.Args[0])
            if (rule.args.test(arg)) {
                return {
                    "Issue": gosec.NewIssue(c, n,
                        rule.metaData.ID, rule.metaData.What,
                        rule.metaData.Severity, rule.metaData.Confidence),
                    "Error": null
                }
            }
        } catch (e) { }
    }
    return {"Issue": null, "Error": null}
}