let metaData = gosec.NewMetaData()
metaData.ID = "G108"
metaData.Severity = gosec.High
metaData.Confidence = gosec.High
metaData.What = "Profiling endpoint is automatically exposed on /debug/pprof"

let rule = {
    "metaData": metaData,
    "importPath": "net/http/pprof",
    "importName": "_",
    "for": ["*ast.ImportSpec"]
}

function replaceAll(current, searchValue, replaceValue) {
    let prev = ""
    while (current !== prev) {
        prev = current
        current = current.replace(searchValue, replaceValue)
    }

    return current
}

function unquote(original) {
    return replaceAll(original.trim(), "\"", "")
}

function match(n, c) {
    let node = utils.transformTo(n, "*ast.ImportSpec")
    if (node !== null) {
        if (rule.importPath === unquote(node.Path.Value) && node.Name !== null && rule.importName === node.Name.Name) {
            return {
                "Issue": gosec.NewIssue(c, node,
                    rule.metaData.ID, rule.metaData.What,
                    rule.metaData.Severity, rule.metaData.Confidence),
                "Error": null
            }
        }
    }
    return {"Issue": null, "Error": null}
}