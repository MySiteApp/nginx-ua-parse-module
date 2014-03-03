# nginx-ua-parse-module

`nginx-ua-parse-module` adds the ability to use [BrowserScope](http://www.browserscope.org)'s user agent strings to parse device, os and browser families into nginx variables.

It converts the [YAML version](https://raw.github.com/tobie/ua-parser/master/regexes.yaml) of the regexes into json that can be replaced without re-building the module into the binary.

Idea came because [we at Brow.si](https://brow.si) searched for efficient way to speed-up analytics data processing, and what's more fast than storing the logged data calcaulated? :)

## Installation

    $ ./configure --add-module=/path/to/nginx-ua-parse-module
    $ make && make install

## Generating regexes.json (requires [Node.js](http://nodejs.org))

    $ npm install
    $ node generate-regexes.js

## Usage
```
    http {
        ...
        log_format userinfo '$remote_addr of kind $ua_parse_device_kind ($ua_parse_device running $ua_parse_os) with $ua_parse_browser';
        uaparse_list /path/to/regexes.json;
        ...
        server {
            ...
            location ... {
                ...
                access_log	logs/userinfo.log userinfo;
                ...
            }
            ...
        }
    }
```

## Credits
* [`tobie/ua-parser`](https://github.com/tobie/ua-parser) for the regexes YAML
