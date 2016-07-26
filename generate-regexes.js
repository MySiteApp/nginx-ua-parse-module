var yaml = require('js-yaml'),
    request = require('request'),
    fs = require('fs');

var OUTPUT = "nginx-regexes.json",
    READ_KEY = {
        "user_agent_parsers": "user_agent_parsers",
        "os_parsers": "os_parsers",
        "device_parsers": "device_parsers",
        "device_brand_parsers": "device_parsers",
        "device_model_parsers": "device_parsers"
    }
    TRANS_IDX = {
        "user_agent_parsers": "browsers",
        "os_parsers": "os",
        "device_parsers": "devices",
        "device_brand_parsers": "brands",
        "device_model_parsers": "models"
    },
    REPLACEMENT_KEY = {
        "user_agent_parsers": "family_replacement",
        "os_parsers": "os_replacement",
        "device_parsers": "device_replacement",
        "device_brand_parsers": "brand_replacement",
        "device_model_parsers": "model_replacement"
    };

function formatFilename() {
    var date = new Date(),
        month = date.getMonth() + 1,
        day = date.getDate();
    if (month < 10) { month = "0" + month; }
    if (day < 10) { day = "0" + day; }
    return date.getFullYear() + "_" + month + "_" + day + "_" + OUTPUT;
}

request('https://raw.githubusercontent.com/ua-parser/uap-core/master/regexes.yaml', function (err, res, body) {
    if (err || res.statusCode != 200) {
        console.error("Failure downloading", err);
        return;
    }
    // Loading
    var obj,
        out = {devices:[], os:[], browsers:[], models:[], brands:[]},
        cur;
    try {
        obj = yaml.safeLoad(body);
    } catch (e) {}
    if (!obj) {
        console.error("Failure parsing", body);
        return;
    }

    // Parsing
    var keys = Object.keys(TRANS_IDX),
        key, i, j, elem,
        os_version_replacement,
        transKey, replacementKey, tempObj;
    for (i = 0; i < keys.length && (key = keys[i], cur = obj[READ_KEY[key]]); i++) {
        transKey = TRANS_IDX[key];
        replacementKey = REPLACEMENT_KEY[key];
        for (j = 0; j < cur.length; j++) {
            elem = cur[j];
            if (!elem.regex) { continue; }
            tempObj = {
                regex: elem.regex
            };
            if (elem[replacementKey]) {
                tempObj.replacement = elem[replacementKey].replace("$1", "%s");
            }
            if (replacementKey == "os_replacement") {
                os_version_replacement = '';
                if (elem['os_v1_replacement']) {
                    os_version_replacement += elem['os_v1_replacement'] + ' ';
                }
                if (elem['os_v2_replacement']) {
                    os_version_replacement += elem['os_v2_replacement'] + ' ';
                }
                if (elem['os_v3_replacement']) {
                    os_version_replacement += elem['os_v3_replacement'] + ' ';
                }
                if (elem['os_v4_replacement']) {
                    os_version_replacement += elem['os_v4_replacement'];
                }
                if (os_version_replacement != '') {
                    tempObj.version_replacement = os_version_replacement.replace("$1", "%s").trim();
                }
            }
            out[transKey].push(tempObj);
        }
    }

    // Writing it out
    var outputFile = formatFilename();
    fs.writeFileSync(outputFile, JSON.stringify(out));
    console.log("Don't forget to copy", outputFile, "and use it with uaparse_list directive");
});
