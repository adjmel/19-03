
document.addEventListener("DOMContentLoaded", function() 
{
    document.getElementById('match_link').addEventListener("click", function(){
        fetch('/jeu/')
        .then(response => response.text())
        .then(text => {
            console.log(text);
            document.querySelector('#content').innerHTML = text;
        });
        fetchScript("jeu.js");
    });
    document.getElementById('ai_link').addEventListener("click", function(){
        fetch('/ordinateur/')
        .then(response => response.text())
        .then(text => {
            console.log(text);
            document.querySelector('#content').innerHTML = text;
        });
        fetchScript("ordinateur.js");
    });
    document.getElementById('tournament_link').addEventListener("click", function(){
        fetch('/tournoi/')
        .then(response => response.text())
        .then(text => {
            console.log(text);
            document.querySelector('#content').innerHTML = text;
        });
        fetchScript("tournoi.js");
    });
});

function fetchScript(value) {
    var script = document.getElementById('extra_script_js');
    if (script)
        script.src = "/static/" + value;
    else {
        script = document.createElement('script');
        script.src = "/static/" + value;
        script.id = 'extra_script_js';
        var index_script = document.getElementById('script_js');
        index_script.parentNode.insertBefore(script, index_script.nextSibling);
    }
}
