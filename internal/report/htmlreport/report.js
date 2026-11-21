// Filters the findings already in the page by severity, status and text.
// It only shows or hides elements and writes a count: it never builds markup
// from report data (THREAT_MODEL.md).
(function () {
  'use strict';
  var form = document.getElementById('filters');
  if (!form) {
    return;
  }
  var boxes = form.querySelectorAll('input[type=checkbox]');
  var status = form.querySelector('select');
  var search = form.querySelector('input[type=search]');
  var shown = document.getElementById('shown');
  var findings = document.querySelectorAll('article.finding');
  function apply() {
    var wanted = {};
    boxes.forEach(function (b) { wanted[b.value] = b.checked; });
    var st = status.value;
    var text = search.value.toLowerCase();
    var n = 0;
    findings.forEach(function (a) {
      var ok = wanted[a.dataset.severity] !== false &&
        (st === '' || a.dataset.status === st) &&
        (text === '' || a.dataset.text.indexOf(text) >= 0);
      a.hidden = !ok;
      if (ok) {
        n++;
      }
    });
    shown.textContent = String(n);
  }
  form.addEventListener('input', apply);
  form.addEventListener('change', apply);
  form.addEventListener('submit', function (e) { e.preventDefault(); });
  form.hidden = false;
  apply();
}());
