let metaData = gosec.NewMetaData()
metaData.ID = "G502"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.High
metaData.What = "Blocklisted import crypto/des: weak cryptographic primitive"

let rule = {
    "metaData": metaData,
    "blocklisted": "crypto/des",
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
    if (node !== null && unquote(node.Path.Value) === rule.blocklisted) {
        return {
            "Issue": gosec.NewIssue(c, n,
                rule.metaData.ID, rule.metaData.What,
                rule.metaData.Severity, rule.metaData.Confidence),
            "Error": null
        }
    }

    return {"Issue": null, "Error": null}
}