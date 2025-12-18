
import { z } from 'zod'

export const AuthBodySchema = z.object({
  username: z.string().min(3).max(32),
  password: z.string().min(6).max(128),
})

export type AuthBodyType = z.infer<typeof AuthBodySchema>

// AuthBody parses the request body and returns a SignUpData object
export const AuthBody = async (req: Request) => {
    const body = await req.json();
    return AuthBodySchema.safeParse(body);
};