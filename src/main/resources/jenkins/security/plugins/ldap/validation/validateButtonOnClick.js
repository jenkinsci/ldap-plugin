
Behaviour.specify(".ldap-validate-input-button-reference-holder", 'ldap-validate', 0, function (e) {
    var validateinp = document.getElementById("ldap-validate-input");
    validateinp.onclick = function(el) {
       return false;
    }
});