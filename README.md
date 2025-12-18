# simple-roll-own-auth

To install dependencies:

```bash
bun install
```

To run:

```bash
bun run index.ts
```

# What is included?

- Makes a server
- Backed by a SQLite database
- Hash passwords with bcrypt and salt
- Issue JWTs on valid login
- Request body validation with zod

Not trivial but less than 500 lines of code, with dependency injection for testability.

Bun helps with the server and database. If you don't use Bun, you'll need to install some kind of database and choose your favorite server package.

## What is not included?

- Rotating peppers for passwords
- Rotating JWT secrets on a weekly cadence


This project was created using `bun init` in bun v1.2.19. [Bun](https://bun.com) is a fast all-in-one JavaScript runtime.
