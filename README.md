# nginx-ua-parse-module

`nginx-ua-parse-module` adds the ability to use [BrowserScope](http://www.browserscope.org)'s user agent strings to parse device, os and browser families into nginx variables.

It converts the [YAML version](https://raw.githubusercontent.com/ua-parser/uap-core/master/regexes.yaml) of the regexes into json that can be replaced without re-building the module into the binary.

Idea came because [we at Brow.si](https://brow.si) searched for efficient way to speed-up analytics data processing, and what's more fast than storing the logged data calculated? :)

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
        log_format userinfo '$remote_addr of kind $ua_parse_device_kind ($ua_parse_device running $ua_parse_os, device brand $ua_parse_device_brand, device model $ua_parse_device_model) with $ua_parse_browser version $ua_parse_browser_ver';
        ...
        server {
            uaparse_list /path/to/regexes.json;  # specify regexes file
            ...
            location ... {
                ...
                uaparse_enable on;  # enable useragent parsing here
                access_log	logs/userinfo.log userinfo;
                ...
            }
            ...
        }
    }
```

### `uaparse_list` directive

`uaparse_list` directive is used on server level to specify regexes file for given server. Argument given to this directive is path to file.

### `uaparse_enable` directive

`uaparse_enable` directive is used on server/location level to enable UA parsing on given server. *Please note* that it is off by default and must be enabled explicitly on server or location level, so regexes arrays are not iterated on every request.

### `uaparse_var` directive

`uaparse_var` directive is used to explicitly specify the variable UA will be taken from.

## Credits
* [`tobie/ua-parser`](https://github.com/tobie/ua-parser) for the regexes YAML
