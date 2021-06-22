let metaData = gosec.NewMetaData()
metaData.ID = "G301"
metaData.Severity = gosec.Medium
metaData.Confidence = gosec.High

let rule = {
    "metaData": metaData,
    "pkgs": ["os"],
    "calls": ["Mkdir", "MkdirAll"],
    "for": ["*ast.CallExpr"]
}

function getConfiguredMode(conf, configKey, defaultMode) {
    let mode = defaultMode
    if (conf.hasOwnProperty(configKey)) {
        let value = conf[configKey]
        switch (typeof value) {
            case "number":
                mode = value
                break
            case "string":
                if (value[0] === "0") {
                    if (value[1].toLowerCase() === "x") {
                        mode = parseInt(value, 16)
                    } else {
                        mode = parseInt(value, 8)
                    }
                } else {
                    mode = defaultMode
                }
                break
        }
    }
    return mode
}

function match(n, c) {
    for (let pkg of rule.pkgs) {
        
    }
}