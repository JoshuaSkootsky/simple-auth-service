console.log("Hello via Bun!");

import { Database } from 'bun:sqlite'
import { createAuthService, type AuthConfig } from './auth-service';
import { createServer } from './server-factory';

const PORT = Number(process.env.PORT ?? 3000)

// Initialize DB
const db = new Database('db.sqlite')
db.run(await Bun.file('schema.sql').text())


// SALT_ROUNDS for bcrypt
const SALT_ROUNDS = 10

// JWT_SECRET for JWT
const JWT_SECRET = process.env.JWT_SECRET ?? 'secret'

// JWT_EXPIRE_TIME for JWT
const JWT_EXPIRE_TIME = process.env.JWT_EXPIRE_TIME ?? '7d'

// Create auth configuration
const authConfig: AuthConfig = {
  salt: SALT_ROUNDS,
  jwtSecret: JWT_SECRET,
  jwtExpireTime: JWT_EXPIRE_TIME,
}

// Create auth service with dependencies
const authService = createAuthService(db, authConfig)

// Create and start server
const { server } = createServer(authService, { port: PORT })

// Export for potential testing use
export { authService, server }