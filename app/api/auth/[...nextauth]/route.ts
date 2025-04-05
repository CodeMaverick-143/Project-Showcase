import NextAuth from "next-auth"
import type { NextAuthOptions } from "next-auth"
import type { JWT } from "next-auth/jwt"
import type { Session } from "next-auth"
import CredentialsProvider from "next-auth/providers/credentials"
import bcrypt from "bcryptjs"
import dbConnect from "@/lib/database"
import User from "@/models/User"

// Extend the built-in session types
declare module "next-auth" {
  interface Session {
    user: {
      id: string
      name?: string | null
      email?: string | null
      image?: string | null
      role?: string
      token?: string
      githubUsername?: string
    }
  }
}

// Define AuthUser type to avoid recursive reference
interface AuthUser {
  id: string
  name: string
  email: string
  role?: string
  image?: string
  githubUsername?: string
}

// Update the authOptions object to include the correct callback URL and session strategy
export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials): Promise<AuthUser | null> {
        try {
          if (!credentials?.email || !credentials?.password) {
            console.log("Error: Missing credentials")
            throw new Error("Email and password are required")
          }

          try {
            await dbConnect()
            console.log("Database connected successfully")
          } catch (dbError) {
            console.error("MongoDB Connection Error:", dbError)
            throw new Error("Database connection failed. Please check your MongoDB configuration.")
          }

          console.log("Searching for user with email:", credentials.email)
          // Find user by email
          const user = await User.findOne({ email: credentials.email }).select("+password")
          console.log("User search complete", user ? "User found" : "No user found")

          if (!user) {
            console.log("Error: No user found with this email")
            throw new Error("No user found with this email")
          }

          console.log("Comparing passwords")
          // Compare passwords
          const isPasswordValid = await bcrypt.compare(credentials.password, user.password)
          console.log("Password validation:", isPasswordValid ? "Valid" : "Invalid")

          if (!isPasswordValid) {
            console.log("Error: Invalid password")
            throw new Error("Invalid password")
          }

          return {
            id: user._id.toString(),
            name: user.name,
            email: user.email,
            role: user.role || "user",
            image: user.profilePicture,
            githubUsername: user.githubUsername,
          }
        } catch (error) {
          console.error("Auth error:", error)
          throw error
        }
      },
    }),
  ],
  session: {
    strategy: "jwt" as const,
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        // Using the AuthUser type defined above
        token.id = user.id
        token.role = (user as AuthUser).role || "user"
        token.githubUsername = (user as AuthUser).githubUsername
      }
      return token
    },
    async session({ session, token }: { session: Session; token: JWT }) {
      if (session.user) {
        session.user.id = token.id as string
        session.user.role = token.role as string
        session.user.githubUsername = token.githubUsername as string
      }
      return session
    },
  },
  pages: {
    signIn: "/login",
    error: "/login",
    newUser: "/signup",
  },
  secret: process.env.NEXTAUTH_SECRET,
  debug: process.env.NODE_ENV === "development",
}

const handler = NextAuth(authOptions)

export { handler as GET, handler as POST }

