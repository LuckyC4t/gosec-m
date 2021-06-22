let metaData = gosec.NewMetaData()
metaData.ID = "G307"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.High
// metaData.What 字符串拼接 放函数里面了

let deferTypes = [
    {
        "typ": "os.File",
        "methods": ["Close"]
    }
]

let rule = {
    "metaData": metaData,
    "types": deferTypes,
    "for": ["*ast.DeferStmt"]
}

function normalize(typ) {
    return typ.replace("*", "")
}

function contains(methods, method) {
    for (let m of methods) {
        if (m === method) {
            return true
        }
    }
    return  false
}

function match(n, c) {
    if (utils.isType(n, "*ast.DeferStmt")) {
        let deferStmt = utils.transformTo(n, "*ast.DeferStmt")
        for (let deferTyp of rule.types) {
            try {
                let res = gosec.GetCallInfo(deferStmt.Call, c)
                let typ = res[0]
                let method = res[1]

                if (normalize(typ) === deferTyp.typ && contains(deferTyp.methods, method)) {
                    let issue = gosec.NewIssue(c, n,
                        rule.metaData.ID, "Deferring unsafe method "+ method +" on type "+ typ,
                        rule.metaData.Severity, rule.metaData.Confidence)

                    return {
                        "Issue": issue,
                        "Error": null
                    }
                }
            } catch (e) {
                // if err != nil { pass }
            }
        }
    }

    return {
        "Issue": null,
        "Error": null
    }
}