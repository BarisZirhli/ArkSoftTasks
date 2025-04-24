"use strict";

var commentsList = [];

function loadComments() {
  var response, data;
  return regeneratorRuntime.async(function loadComments$(_context) {
    while (1) {
      switch (_context.prev = _context.next) {
        case 0:
          _context.next = 2;
          return regeneratorRuntime.awrap(fetch('https://jsonplaceholder.typicode.com/comments'));

        case 2:
          response = _context.sent;
          _context.next = 5;
          return regeneratorRuntime.awrap(response.json());

        case 5:
          data = _context.sent;
          data.forEach(function (comment) {
            commentsList.push({
              id: comment.id,
              name: comment.name,
              email: comment.email,
              body: comment.body
            });
          }); // Veri hazır, burada güvenle kullanabilirsin:

          useComments(commentsList);

        case 8:
        case "end":
          return _context.stop();
      }
    }
  });
}

function useComments(list) {
  list.forEach(function (comment) {
    console.log("ID: ".concat(comment.id, ", Name: ").concat(comment.name, ", Email: ").concat(comment.email, ", Body: ").concat(comment.body));
  });
}

loadComments(); // çağırınca çalışır