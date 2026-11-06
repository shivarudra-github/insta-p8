import { type NextRequest, NextResponse } from "next/server"
import { authenticateRequest } from "@/lib/auth-session"

export async function GET(request: NextRequest) {
  const auth = await authenticateRequest(request)
  if (auth.errorResponse) {
    return auth.errorResponse
  }

  return NextResponse.json({
    authenticated: true,
    user: {
      userId: auth.session.userId,
      username: auth.session.username,
    },
  })
}

