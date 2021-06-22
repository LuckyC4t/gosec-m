let metaData = gosec.NewMetaData()
metaData.ID = "G402"

let rule = {
    "metaData": metaData,
    "requiredType": "crypto/tls.Config",
    "MinVersion":   0x0303,
    "MaxVersion":   0x0304,
    "goodCiphers": [
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    ],
    "for": ["*ast.CompositeLit"]
}

function stringInSlice(a, list) {
    for (let b of list) {
        if (b === a) {
            return true
        }
    }
    return false
}

function processTLSCipherSuites(n, c) {
    let ciphers = utils.transformTo(n, "*ast.CompositeLit")
    if (ciphers !== null) {
        for (let cipher of ciphers.Elts) {
            let ident = utils.transformTo(cipher, "*ast.SelectorExpr")
            if (ident !== null && !stringInSlice(ident.Sel.Name, rule.goodCiphers)) {
                return gosec.NewIssue(c, ident, rule.metaData.ID, "TLS Bad Cipher Suite: "+ident.Sel.Name, gosec.High, gosec.High)
            }
        }
    }
    return null
}

function mapVersion(version) {
    let v = 0
    switch (version) {
        case "VersionTLS13":
            v = 0x0304
            break
        case "VersionTLS12":
            v = 0x0303
            break
        case "VersionTLS11":
            v = 0x0302
            break
        case "VersionTLS10":
            v = 0x0301
            break
    }
    return v
}

function processTLSConfVal(n, c) {
    let ident = utils.transformTo(n.Key, "*ast.Ident")
    if (ident !== null) {
        switch (ident.Name) {
            case "InsecureSkipVerify":
                let node = utils.transformTo(n.Value, "*ast.Ident")
                if (node !== null && node.Name !== "false") {
                    return gosec.NewIssue(c, n, rule.metaData.ID, "TLS InsecureSkipVerify set true.", gosec.High, gosec.High)
                } else  {
                    return gosec.NewIssue(c, n, rule.metaData.ID, "TLS InsecureSkipVerify may be true.", gosec.High, gosec.Low)
                }

            case "PreferServerCipherSuites":
                node = utils.transformTo(n.Value, "*ast.Ident")
                if (node !== null && node.Name !== "false") {
                    return gosec.NewIssue(c, n, rule.metaData.ID, "TLS PreferServerCipherSuites set false.", gosec.Medium, gosec.High)
                } else  {
                    return gosec.NewIssue(c, n, rule.metaData.ID, "TLS PreferServerCipherSuites may be false.", gosec.Medium, gosec.Low)
                }

            case "MinVersion":
                try {
                    rule.actualMinVersion = gosec.GetInt(n.Value)
                } catch (e) {
                    let se = utils.transformTo(n.Value, "*ast.SelectorExpr")
                    if (se !== null) {
                        let pkg = utils.transformTo(se.X, "*ast.Ident")
                        if (pkg !== null && pkg.Name === "tls") {
                            rule.actualMinVersion = mapVersion(se.Sel.Name)
                        }
                    }
                }
                break
            case "MaxVersion":
                try {
                    rule.actualMaxVersion = gosec.GetInt(n.Value)
                } catch (e) {
                    let se = utils.transformTo(n.Value, "*ast.SelectorExpr")
                    if (se !== null) {
                        let pkg = utils.transformTo(se.X, "*ast.Ident")
                        if (pkg !== null && pkg.Name === "tls") {
                            rule.actualMaxVersion = mapVersion(se.Sel.Name)
                        }
                    }
                }
                break
            case "CipherSuites":
                let ret = processTLSCipherSuites(n.Value, c)
                if (ret !== null) {
                    return ret
                }
                break
        }
    }

    return null
}

function checkVersion(n, c) {
    if (rule.actualMaxVersion === 0 && rule.actualMinVersion >= rule.MinVersion) {
        return null
    }

    if (rule.actualMinVersion < rule.MinVersion) {
        return gosec.NewIssue(c, n, rule.metaData.ID, "TLS MinVersion too low.", gosec.High, gosec.High)
    }

    if (rule.actualMaxVersion < rule.MaxVersion) {
        return gosec.NewIssue(c, n, rule.metaData.ID, "TLS MaxVersion too low.", gosec.High, gosec.High)
    }
    return null
}

function resetVersion() {
    rule.actualMaxVersion = 0
    rule.actualMinVersion = 0
}

function match(n, c) {
    let complit = utils.transformTo(n, "*ast.CompositeLit")
    if (complit !== null && complit.Type !== null) {
        let actualType = c.Info.TypeOf(complit.Type)
        if (actualType !== null && actualType.String() === rule.requiredType) {
            for (let elt of complit.Elts) {
                let kve = utils.transformTo(elt, "*ast.KeyValueExpr")
                if (kve !== null) {
                    let issue = processTLSConfVal(kve, c)
                    if (issue !== null) {
                        return {"Issue": issue, "Error": null}
                    }
                }
            }

            let issue = checkVersion(complit, c)
            resetVersion()
            return {"Issue": issue, "Error": null}
        }
    }

    return {"Issue": null, "Error": null}
}