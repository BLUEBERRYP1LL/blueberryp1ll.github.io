// Wartet, bis die Seite vollständig geladen ist
document.addEventListener('DOMContentLoaded', function(){

  // Prüft, ob ein Element mit der ID "typed" existiert
  var typedElement = document.querySelector('#typed');
  if (typedElement) {
    // Wenn ja, starte Typed.js
    var typed = new Typed(typedElement, {
      strings: ["I analyze vulnerabilities.", "I secure networks.", "I break and build.", "I am a Cybersecurity Professional."],
      typeSpeed: 50,  // Geschwindigkeit beim Tippen
      backSpeed: 30,  // Geschwindigkeit beim Löschen
      loop: true,     // Endlosschleife
      showCursor: true,
      cursorChar: '_',
    });
  }

});
