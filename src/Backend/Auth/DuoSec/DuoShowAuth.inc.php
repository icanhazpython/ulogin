<?php

// ********************************
//	DO NOT MODIFY
// ********************************
namespace Ulogin\Backend\Auth\DuoSec;

use Ulogin\Utilities;
use Ulogin\Nonce;

$returnUrl = Utilities::CurrentURL();
$sig_request = Duo::signRequest(UL_DUOSEC_IKEY, UL_DUOSEC_SKEY, UL_DUOSEC_AKEY, $uid);

// ********************************
//	MAKE MODIFICATION BELOW WHERE NOTED
//  If possible, only insert but do not modify
// ********************************

// ********************************
//	Your HTML here
//  doctype, head, title etc.
// ********************************

?>
    <script src="<?php echo(UL_DUOSEC_JQUERY_URI); ?>"></script>
    <script>
        (function (a) {
            var d, f, e = 1, i, j = this, k, l = j.postMessage && !a.browser.opera;
            a.postMessage = function (b, c, h) {
                if (c) {
                    b = typeof b === "string" ? b : a.param(b);
                    h = h || parent;
                    if (l)h.postMessage(b, c.replace(/([^:]+:\/\/[^\/]+).*/, "$1")); else if (c)h.location = c.replace(/#.*$/, "") + "#" + +new Date + e++ + "&" + b
                }
            };
            a.receiveMessage = k = function (b, c, h) {
                if (l) {
                    if (b) {
                        i && k();
                        i = function (g) {
                            if (typeof c === "string" && g.origin !== c || a.isFunction(c) && c(g.origin) === false)return false;
                            b(g)
                        }
                    }
                    if (j.addEventListener)j[b ? "addEventListener" : "removeEventListener"]("message",
                        i, false); else j[b ? "attachEvent" : "detachEvent"]("onmessage", i)
                } else {
                    d && clearInterval(d);
                    d = null;
                    if (b)d = setInterval(function () {
                        var g = document.location.hash, m = /^#?\d+&/;
                        if (g !== f && m.test(g)) {
                            f = g;
                            b({data: g.replace(m, "")})
                        }
                    }, typeof c === "number" ? c : typeof h === "number" ? h : 100)
                }
            }
        })(jQuery);
        var Duo = {
            init: function (a) {
                if (a)if (a.host) {
                    Duo._host = a.host;
                    if (a.sig_request) {
                        Duo._sig_request = a.sig_request;
                        if (Duo._sig_request.indexOf("ERR|") == 0) {
                            a = Duo._sig_request.split("|");
                            alert("Error: " + a[1])
                        } else if (Duo._sig_request.indexOf(":") == -1)alert("Invalid sig_request value"); else {
                            var d = Duo._sig_request.split(":");
                            if (d.length != 2)alert("Invalid sig_request value"); else {
                                Duo._duo_sig = d[0];
                                Duo._app_sig = d[1];
                                if (!a.post_action)a.post_action = "";
                                Duo._post_action = a.post_action;
                                if (!a.post_argument)a.post_argument =
                                    "sig_response";
                                Duo._post_argument = a.post_argument
                            }
                        }
                    } else alert("Error: missing 'sig_request' argument in Duo.init()")
                } else alert("Error: missing 'host' argument in Duo.init()"); else alert("Error: missing arguments in Duo.init()")
            }, ready: function () {
                var a = $("#duo_iframe");
                if (a.length) {
                    var d = $.param({tx: Duo._duo_sig, parent: document.location.href});
                    a.attr("src", "https://" + Duo._host + "/frame/web/v1/auth?" + d);
                    $.receiveMessage(function (f) {
                        f = f.data + ":" + Duo._app_sig;
                        f = $('<input type="hidden">').attr("name",
                            Duo._post_argument).val(f);
                        var e = $("#duo_form");
                        if (!e.length) {
                            e = $("<form>");
                            e.insertAfter(a)
                        }
                        e.attr("method", "POST");
                        e.attr("action", Duo._post_action);
                        e.append(f);
                        e.submit()
                    }, "https://" + Duo._host)
                } else alert("Error: missing IFRAME element with id 'duo_iframe'")
            }
        };
        $(document).ready(function () {
            Duo.ready()
        });
    </script>
    <script>
        Duo.init({
            'host': '<?php echo(UL_DUOSEC_HOST); ?>',
            'post_action': '<?php echo($returnUrl);?>',
            'sig_request': '<?php echo($sig_request); ?>'
        });
    </script>

    <?php
// ********************************
//	Your HTML here
//  header, body, text, etc.
// ********************************
?>

    <iframe id="duo_iframe" width="500" height="800" frameborder="0" allowtransparency="true"
            style="background: transparent;"></iframe>
    <form method="POST" id="duo_form">
        <input type="hidden" name="ulDuoSecLoginNonce" value="<?php echo Nonce::Create('ulDuoSecLogin'); ?>"/>
    </form>

    <?php

// ********************************
//	Your HTML here
//  body, text, footer etc.
// ********************************
