
 Behaviour.specify(".ldap-validate-button-reference-holder", 'ldap-validate', 0, function (e) {
     var url = e.getAttribute('data-fullurl');
     var attr = e.getAttribute('data-attributes')
     var id = e.getAttribute('data-id');
     var button = document.getElementById(id);
     button.onclick = function(el) {
        ldapValidateButton(url,attr,this,id);
        return false;
     }
 });