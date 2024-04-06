Behaviour.specify("DIV.ldap-validate-form", 'ldap-validate', -200, function (div) {
    const id = div.getAttribute("id");
    if (window['ldap validate'] === undefined) {
        window['ldap validate'] = {};
    }
    if (window['ldap validate'][id] === undefined) {
        window['ldap validate'][id] = div.innerHTML;
        div.innerHTML = '';
    }
    div = null; // avoid memory leak
});

function ldapValidateButton(button, dataset) {
    const checkUrl = dataset['fullurl'];
    const formFilter = dataset['attributes']
    const id = dataset['id'];
    const submitText = dataset['submit'];
    const dialogTitle = dataset['dialogtitle'];

    const form = button.closest("FORM");
    buildFormTree(form);
    let json = JSON.parse(form['json'].value);
    if (formFilter) {
        let cur = json;
        json = {};
        const path = formFilter.split('.');
        for (let i = 0; i < path.length; i++) {
            cur = cur[path[i]];
            if (i === path.length - 1) {
                json[path[i]] = cur;
            }
        }
    }

    function validateSubmit(validationForm) {
        const spinner = document.getElementById(id + "_spinner");
        const target = spinner.closest('.jenkins-form-item').querySelector(".validation-error-area");
        spinner.style.display = "block";
        const inputs = validationForm.querySelectorAll("input");
        for (let i = 0; i < inputs.length; i++) {
            json[inputs[i].name] = inputs[i].value;
        }
        fetch(checkUrl, {
            method: "post",
            headers: crumb.wrap({
                "Content-Type": "application/json",
            }),
            body: JSON.stringify(json),
        }).then(function(rsp) {
            rsp.text().then((responseText) => {
                spinner.style.display = "none";
                target.innerHTML = `<div class="validation-error-area" />`;
                updateValidationArea(target, responseText);
                layoutUpdateCallback.call();
            });
        });
    }
    try {
        const dialogDiv = document.createElement("DIV");
        document.body.appendChild(dialogDiv);
        dialogDiv.innerHTML = "<form></form>";
        const dialogBody = dialogDiv.firstElementChild;
        dialogBody.innerHTML = window['ldap validate'][id+"_div"];
        dialog.form(dialogBody, {okText: submitText, title:dialogTitle,
                minWidth: "50vw", submitButton: false}).then(() => validateSubmit(dialogBody));
        const input = dialogBody.querySelector("INPUT");
        input && input.focus();
    } catch (e) {
        console.log(e);
    }
}

