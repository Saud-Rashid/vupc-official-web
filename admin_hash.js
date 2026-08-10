// Run locally: node generate-admin-hash.js "YourNewStrongPassword"
// Paste the printed ADMIN_PASSWORD_HASH and JWT_SECRET into:
//   1) your local .env (for testing)
//   2) Vercel Dashboard -> Project -> Settings -> Environment Variables (for production)
// Never commit the output anywhere.

const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const newPassword = process.argv[2];

if (!newPassword || newPassword.length < 10) {
  console.error('Usage: node generate-admin-hash.js "@vupc-admin-1234" )');
  process.exit(1);
}

const hash = bcrypt.hashSync(newPassword, 12);
const jwtSecret = crypto.randomBytes(48).toString('hex');

console.log('\nADMIN_PASSWORD_HASH=' + hash);
console.log('JWT_SECRET=' + jwtSecret);
console.log('\nSet both of these as environment variables — do not hardcode them in any file.\n');