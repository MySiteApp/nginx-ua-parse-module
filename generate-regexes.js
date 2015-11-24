var yaml = require('js-yaml'),
    request = require('request'),
    fs = require('fs');

var OUTPUT = "nginx-regexes.json",
    TRANS_IDX = {
        "user_agent_parsers": "browsers",
        "os_parsers": "os",
        "device_parsers": "devices"
    },
    REPLACEMENT_KEY = {
        "user_agent_parsers": "family_replacement",
        "os_parsers": "os_replacement",
        "device_parsers": "device_replacement"
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
        out = {devices:[], os:[], browsers:[]},
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
        transKey, replacementKey, tempObj;
    for (i = 0; i < keys.length && (key = keys[i], cur = obj[key]); i++) {
        transKey = TRANS_IDX[key];
        replacementKey = REPLACEMENT_KEY[key];
        for (j = 0; j < cur.length; j++) {
            elem = cur[j];
            if (!elem.regex) { continue; }

            // Incompatible regexes. `ngx_regex_exec` crashes with these regexes:
            if (elem.regex.indexOf("; *(?:HTC[ _/])+([^ _/]+)(?:[") == 0) { continue; }
            if (elem.regex.indexOf("; *(?:(?:HTC|htc)(?:_blocked)*[ _/])+([^ _/") == 0) { continue; }

            tempObj = {
                regex: elem.regex
            };
            if (elem[replacementKey]) {
                tempObj.replacement = elem[replacementKey].replace("$1", "%s");
            }
            out[transKey].push(tempObj);
        }
    }

    // Writing it out
    var outputFile = formatFilename();
    fs.writeFileSync(outputFile, JSON.stringify(out).replace(/\\\\/g, '\\\\\\'));
    console.log("Don't forget to copy", outputFile, "and use it with uaparse_list directive");
});
