// Test JS file with DOM sinks
function updateContent() {
    var input = document.getElementById('user-input');
    if (input) {
        document.getElementById('output').innerHTML = input.value;
    }
}

function processHash() {
    var hash = location.hash.substring(1);
    document.getElementById('hash-content').innerHTML = hash;
}

function evilEval(data) {
    eval(data);
}

function processMessage(event) {
    document.getElementById('msg').innerHTML = event.data;
}

window.addEventListener('message', processMessage);
