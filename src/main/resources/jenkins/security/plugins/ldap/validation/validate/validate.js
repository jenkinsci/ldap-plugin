Behaviour.specify("DIV.ldap-validate-form", 'ldap-validate', -200, function (div) {
    var id = div.getAttribute("id");
    if (window['ldap validate'] === undefined) {
        window['ldap validate'] = {};
    }
    if (window['ldap validate'][id] === undefined) {
        window['ldap validate'][id] = div.innerHTML;
        div.innerHTML = '';
    }
    div = null; // avoid memory leak
});

function ldapValidateButton(checkUrl, formFilter, button, id) {
    var form = findAncestor(button, "FORM");
    button = button._button;
    buildFormTree(form);
    var json = JSON.parse(form['json'].value);
    if (formFilter) {
        var cur = json;
        json = {};
        var filtered = json;
        var path = formFilter.split('.');
        for (var i = 0; i < path.length; i++) {
            cur = cur[path[i]];
            filtered[path[i]] = i === path.length - 1 ? cur : {};
            filtered = filtered[path[i]];
        }
    }

    try {
        var dialogDiv = document.createElement("DIV");
        document.body.appendChild(dialogDiv);
        dialogDiv.innerHTML = "<div></div>";
        var dialogBody = dialogDiv.firstElementChild;
        dialogBody.innerHTML = window['ldap validate'][id+"_div"];
        var cleanUp = function() {
            dialog.destroy();
            document.body.removeChild(dialogDiv);
            dialogDiv = null;
            dialogBody = null;
            dialog = null;
        };
        var dialog = new YAHOO.widget.Panel(dialogBody, {
            fixedcenter: true,
            close: true,
            draggable: false,
            zindex: 1000,
            modal: true,
            visible: false,
            keylisteners: [
                new YAHOO.util.KeyListener(document, {keys: 27}, {
                    fn: cleanUp,
                    scope: document,
                    correctScope: false
                })
            ]
        });
        dialog.render();
        YAHOO.util.Event.removeListener(dialog.close, "click");
        YAHOO.util.Event.on(dialog.close, "click", cleanUp);
        Behaviour.applySubtree(dialogDiv, true);
        var r = YAHOO.util.Dom.getClientRegion();
        dialog.cfg.setProperty("width", r.width * 1 / 2 + "px");
        dialog.cfg.setProperty("height", "auto");
        dialog.center();
        dialog.show();
        window.setTimeout(function () {
            var inputs = dialogDiv.getElementsByTagName("INPUT");
            if (inputs && inputs.length > 0) {
                inputs[0].focus();
            }
            var buttons = dialogDiv.getElementsByTagName("BUTTON");
            buttons[buttons.length-1].onclick = function () {
                var spinner = document.getElementById(id + "_spinner");
                var target = document.getElementById(id+"_result");
                target.style.display = "none";
                target.innerHTML = '';
                spinner.style.display = "block";
                for (var i = 0; i < inputs.length; i++) {
                    json[inputs[i].name] = inputs[i].value;
                }
                new Ajax.Request(checkUrl, {
                    contentType: "application/json",
                    encoding: "UTF-8",
                    method: 'post',
                    requestHeaders: {'Crumb': crumb},
                    postBody: Object.toJSON(json),
                    onComplete: function (rsp) {
                        spinner.style.display = "none";
                        applyErrorMessage(target, rsp);
                        target.style.display = "block";
                        layoutUpdateCallback.call();
                        var s = rsp.getResponseHeader("script");
                        try {
                            geval(s);
                        } catch (e) {
                            window.alert("failed to evaluate " + s + "\n" + e.message);
                        }
                    }
                });
                cleanUp();
            };
        }, 100);
    } catch (e) {
        console.log(e);
    }
}

