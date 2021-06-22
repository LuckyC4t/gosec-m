let metaData = gosec.NewMetaData()
metaData.ID = "G401"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.High
metaData.What = "Use of weak cryptographic primitive"

let calls = new Map([
        ["crypto/des", ["NewCipher", "NewTripleDESCipher"]],
        ["crypto/md5", ["New", "Sum"]],
        ["crypto/sha1", ["New", "Sum"]],
        ["crypto/rc4", ["NewCipher"]],
])

let rule = {
    "metaData": metaData,
    "blocklist": calls,
    "for": ["*ast.CallExpr"]
}

function match(n, c) {
    for (let pkg of rule.blocklist.keys()) {
        let funcs = rule.blocklist.get(pkg)
        let ret = gosec.MatchCallByPackage(n, c, pkg, funcs)
        if (ret[1]) {
            return {"Issue": gosec.NewIssue(c, n, rule.metaData.ID, rule.metaData.What, rule.metaData.Severity, rule.metaData
                    .Confidence), "Error": null}
        }
    }
    return {"Issue": null, "Error": null}
}