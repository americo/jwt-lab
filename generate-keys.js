const crypto = require("crypto");
const fs = require("fs");

// Generate RSA key pair
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
  },
});

// Save keys to files
fs.writeFileSync("private.pem", privateKey);
fs.writeFileSync("public.pem", publicKey);

console.log("RSA keys generated successfully!");
console.log("Private key saved to private.pem");
console.log("Public key saved to public.pem");
