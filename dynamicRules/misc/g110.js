let metaData = gosec.NewMetaData()
metaData.ID = "G110"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.Medium
metaData.What = "Potential DoS vulnerability via decompression bomb"

let readerCalls = gosec.NewCallList()
readerCalls.Add("compress/gzip", "NewReader")
readerCalls.AddAll("compress/zlib", "NewReader", "NewReaderDict")
readerCalls.Add("compress/bzip2", "NewReader")
readerCalls.AddAll("compress/flate", "NewReader", "NewReaderDict")
readerCalls.Add("compress/lzw", "NewReader")
readerCalls.Add("archive/tar", "NewReader")
readerCalls.Add("archive/zip", "NewReader")
readerCalls.Add("*archive/zip.File", "Open")

let copyCalls = gosec.NewCallList()
copyCalls.Add("io", "Copy")
copyCalls.Add("io", "CopyBuffer")

let rule = {
    "metaData": metaData,
    "readerCalls": readerCalls,
    "copyCalls": copyCalls,
    "for": ["*ast.FuncDecl", "*ast.AssignStmt", "*ast.CallExpr"]
}

function containsReaderCall(node, ctx, list) {
    if (list.ContainsPkgCallExpr(node, ctx, false) !== null) {
        return true
    }

    let res = gosec.GetCallInfo(node, ctx)
    let s = res[0]
    let idt = res[1]
    return list.Contains(s, idt)
}

function match(node, ctx) {
    let readerVarObj = {}
    if (!ctx.PassedValues.hasOwnProperty(rule.metaData.ID)) {
        ctx.PassedValues[rule.metaData.ID] = readerVarObj
    } else {
        readerVarObj = ctx.PassedValues[rule.metaData.ID]
    }

    switch (utils.getGoType(node)) {
        case "*ast.AssignStmt":
        {
            let n = utils.transformTo(node, "*ast.AssignStmt");
            for (let expr of n.Rhs) {
                if (utils.isType(expr, "*ast.CallExpr") && containsReaderCall(utils.transformTo(expr, "*ast.CallExpr"), ctx, rule.readerCalls)) {
                    if (utils.isType(n.Lhs[0], "*ast.Ident")) {
                        let idt = utils.transformTo(n.Lhs[0], "*ast.Ident")
                        readerVarObj[idt.Obj] = {}
                    }
                }
            }
            break
        }

        case "*ast.CallExpr":
        {
            let n = utils.transformTo(node, "*ast.CallExpr");
            if (rule.copyCalls.ContainsPkgCallExpr(n, ctx, false) !== null) {
                if (utils.isType(n.Args[1], "*ast.Ident")) {
                    let idt = utils.transformTo(n.Args[1], "*ast.Ident")
                    if (readerVarObj.hasOwnProperty(idt.Obj)) {
                        return {"Issue":gosec.NewIssue(ctx, n,
                                rule.metaData.ID, rule.metaData.What,
                                rule.metaData.Severity, rule.metaData.Confidence), "Error": null}
                    }
                }
            }
            break
        }
    }

    return {"Issue":null, "Error": null}
}