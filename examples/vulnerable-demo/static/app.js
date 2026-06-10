function render(data) {
  document.getElementById("output").innerHTML = data.userContent;
}

function legacy(msg) {
  document.write(msg);
}
