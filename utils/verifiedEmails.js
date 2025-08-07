// utils/verifiedEmails.js

const verifiedEmails = new Set();

module.exports = {
  add: (email) => verifiedEmails.add(email),
  has: (email) => verifiedEmails.has(email),
  remove: (email) => verifiedEmails.delete(email),
};
