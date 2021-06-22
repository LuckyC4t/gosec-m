let metaData = gosec.NewMetaData()
metaData.ID = "G504"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.High
metaData.What = "Blocklisted import net/http/cgi: Go versions < 1.6.3 are vulnerable to Httpoxy attack: (CVE-2016-5386)"

let rule = {
    "metaData": metaData,
    "blocklisted": "net/http/cgi",
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
    if (utils.isType(n, "*ast.ImportSpec")) {
        let node = utils.transformTo(n, "*ast.ImportSpec")
        if (unquote(node.Path.Value) === rule.blocklisted) {
            return {
                "Issue": gosec.NewIssue(c, n,
                    rule.metaData.ID, rule.metaData.What,
                    rule.metaData.Severity, rule.metaData.Confidence),
                "Error": null
            }
        }
    }

    return {"Issue": null, "Error": null}
}