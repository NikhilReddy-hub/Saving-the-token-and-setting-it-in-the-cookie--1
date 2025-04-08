const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Replace these with environment variables in production
const JWT_SECRET = 'your_jwt_secret';
const ENCRYPTION_KEY = crypto.randomBytes(32); // 32 bytes for AES-256
const IV = crypto.randomBytes(16); // 16 bytes IV

const encrypt = (payload) => {
  // Step 1: Create JWT
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

  // Step 2: Encrypt the JWT
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, IV);
  let encrypted = cipher.update(token, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Combine IV and encrypted token
  return IV.toString('hex') + ':' + encrypted;
};

const decrypt = (encryptedToken) => {
  const [ivHex, encrypted] = encryptedToken.split(':');

  const iv = Buffer.from(ivHex, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  // Verify JWT
  const decoded = jwt.verify(decrypted, JWT_SECRET);
  return decoded;
};

// Example usage
const payload = { userId: 123, role: 'admin' };
const encryptedToken = encrypt(payload);
const decryptedPayload = decrypt(encryptedToken);

// Check success
if (decryptedPayload.userId === payload.userId && decryptedPayload.role === payload.role) {
  console.log('Success');
} else {
  console.log('Failed');
}

module.exports = {
  encrypt,
  decrypt
};
