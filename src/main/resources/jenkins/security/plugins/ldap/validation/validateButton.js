
 Behaviour.specify(".ldap-validate-button-reference-holder", 'ldap-validate', 0, function (e) {
     const button = document.getElementById(e.dataset['id']);
     button.onclick = function(el) {
        ldapValidateButton(this, e.dataset);
        return false;
     }
 });