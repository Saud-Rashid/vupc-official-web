// Vercel serverless entry point.
// vercel.json declares "src": "api/index.js" as the build target for every
// /api/* route — this file MUST exist at this exact path or Vercel has
// nothing to deploy the API routes to (this was the missing piece causing
// admin login, and every other /api call, to fail in production).
//
// The actual Express app and all route logic still live in server.js at the
// project root, unchanged in architecture — this file only re-exports it.
module.exports = require('../server.js');