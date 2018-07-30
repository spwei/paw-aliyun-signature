(function() {
    var pad = function(num) {
        var r = '00' + num;
        return r.substring(r.length - 2);
    };

    var str2asc = function str2asc(strstr) {
        return ("0" + strstr.charCodeAt(0).toString(16)).slice(-2);
    };

    var asc2str = function asc2str(ascasc) {
        return String.fromCharCode(ascasc);
    };

    var urlEncode = function UrlEncode(str) {
        var ret = "";
        var strSpecial = "!\"#$%&'()*+,/:;<=>?[]^`{|}~%@\\";
        var tt = "";

        for (var i = 0; i < str.length; i++) {
            var chr = str.charAt(i);
            var c = str2asc(chr);
            tt += chr + ":" + c + "n";
            if (parseInt("0x" + c) > 0x7f) {
                ret += "%" + c.slice(0, 2) + "%" + c.slice(-2);
            } else {
                if (chr == " ")
                    ret += "+";
                else if (strSpecial.indexOf(chr) != -1)
                    ret += "%" + c.toString(16).toUpperCase();
                else
                    ret += chr;
            }
        }
        return ret;
    };

    var urlDecode = function UrlDecode(str) {
        var ret = "";
        for (var i = 0; i < str.length; i++) {
            var chr = str.charAt(i);
            if (chr == "+") {
                ret += " ";
            } else if (chr == "%") {
                var asc = str.substring(i + 1, i + 3);
                if (parseInt("0x" + asc) > 0x7f) {
                    ret += asc2str(parseInt("0x" + asc + str.substring(i + 4, i + 6)));
                    i += 5;
                } else {
                    ret += asc2str(parseInt("0x" + asc));
                    i += 2;
                }
            } else {
                ret += chr;
            }
        }
        return ret;
    };

    Date.prototype.toISOString = function() {
        return this.getUTCFullYear() +
            '-' + pad(this.getUTCMonth() + 1) +
            '-' + pad(this.getUTCDate()) +
            'T' + pad(this.getUTCHours()) +
            ':' + pad(this.getUTCMinutes()) +
            ':' + pad(this.getUTCSeconds()) +
            'Z';
    };

    var identifier = 'com.weibo.api.AliyunSignature';

    var AliyunSignature = function() {
        var sep = '&';

        var percent = function(s) {
            s = s.replace(/\+/g, '%20');
            s = s.replace(/\*/g, '%2A');
            s = s.replace(/%7E/g, '~');
            return s;
        };

        var percentEncode = function(s) {
            s = urlEncode(s);
            s = percent(s);
            return s;
        };

        var signParams = function(httpMethod, userParams, keySecret) {
            // console.log(userParams);
            // 分离参数KV
            var kvs = userParams.replace(/^&|&$/, '').split(sep);
            var keys = [];
            var params = {};
            for (var i = 0; i < kvs.length; i++) {
                const position = kvs[i].indexOf('=');
                if (position < 0) {
                    continue;
                }

                var key = kvs[i].substring(0, position);
                keys.push(key);
                params[key] = kvs[i].substring(position + 1);
                // console.log(key + "  " + params[key]);
            }

            // 排序
            keys.sort();

            // 规范化字符串
            var sortedParams = [];
            var encodeKey, encodeValue;
            for (var i = 0; i < keys.length; i++) {
                encodeKey = percentEncode(keys[i]);
                encodeValue = percentEncode((params[keys[i]]));
                // console.log(encodeKey + "  " + encodeValue);
                sortedParams.push(encodeKey + '=' + encodeValue);
            }
            var canonicalized = percentEncode(sortedParams.join(sep));
            var strToSign = httpMethod + sep + percentEncode('/') + sep + canonicalized;
            // console.log(strToSign);

            // 签名
            var dynamicValue = DynamicValue('com.luckymarmot.HMACDynamicValue', {
                'input': strToSign,
                'key': keySecret + sep,
                'algorithm': 1 // HMAC-SHA1
            });

            // 返回签名值
            return DynamicString(dynamicValue).getEvaluatedString();
        };

        var getUserParametersFromUrl = function(request) {
            var ds = request.getUrl(true);
            var newDs = DynamicString();
            var components = ds.components;
            for (var i = 0; i < ds.length; i++) {
                var c = components[i];
                if (c) {
                    if (typeof c === 'string') {
                        // Paw的字符串是经过编码的，但是没有对=编码
                        newDs.appendString(urlDecode(c));
                    } else {
                        if (c.type !== identifier) {
                            newDs.appendString(c.getEvaluatedString());
                        }
                    }
                }
            }
            var str = newDs.getEvaluatedString();
            // console.log(str);
            return str.replace(/^https?:\/\/[^\/]+[\/\?]*/, '').replace(/Signature=&?/, '').replace(/^&|&$/, '');
        };

        var getUserParametersFromBody = function(request) {
            var params = [];
            var bodyParameters = request.getUrlEncodedBody(true);
            for (var key in bodyParameters) {
                if (key === "Signature") {
                    continue;
                }
                var value = bodyParameters[key]; // DynamicString
                params.push(key + "=" + value.getEvaluatedString());
            }
            return params.join(sep);
        };

        var evaluateRawString = function(env, request) {
            var httpMethod = request.method;
            var userParams = getUserParametersFromUrl(request) + sep + getUserParametersFromBody(request);
            var keyId = env.keyId;
            var resourceOwnerAccount = env.resourceOwnerAccount;
            var format = 'JSON';
            if (env.format != '') {
                format = env.format;
            }
            var version = env.version;
            var curDate = new Date();
            var timeStamp = curDate.toISOString();
            var signatureNonce = "paw-sn-" + curDate.getTime();
            var commonParams = 'Format=' + format +
                '&Version=' + version +
                '&AccessKeyId=' + keyId +
                '&SignatureMethod=HMAC-SHA1' +
                '&SignatureVersion=1.0' +
                '&SignatureNonce=' + signatureNonce +
                '&Timestamp=' + timeStamp;
            if (resourceOwnerAccount != '') {
                commonParams += '&ResourceOwnerAccount=' + resourceOwnerAccount;
            }

            var signature = signParams(httpMethod, userParams + sep + commonParams, env.keySecret);
            return urlEncode(signature) + sep + commonParams;
        };

        this.evaluate = function(context) {
            var request = context.getCurrentRequest();
            if (request == undefined) {
                return '';
            }

            var httpMethod = request.method;
            if (httpMethod != "GET" && httpMethod != "POST") {
                return '';
            }

            return evaluateRawString(this, request);
        };
    };

    AliyunSignature.identifier = identifier;
    AliyunSignature.title = "AliyunSignature";
    AliyunSignature.inputs = [
        DynamicValueInput("keyId", "Access Key Id", "String"),
        DynamicValueInput("keySecret", "Access Key Secret", "String"),
        DynamicValueInput("resourceOwnerAccount", "Resource Owner Account", "String"),
        DynamicValueInput("format", "Format", "String"),
        DynamicValueInput("version", "Version", "String")
    ];

    registerDynamicValueClass(AliyunSignature);
}).call(this);