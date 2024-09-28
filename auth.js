import NextAuth from 'next-auth';
import Google from 'next-auth/providers/google';
import Credentials from 'next-auth/providers/credentials';
import { userTable, connectToDatabase } from './db'; // Adjust path if needed

export const { handlers, signIn, signOut, auth } = NextAuth({
  strategy: 'jwt',
  secret: process.env.SECRET,
  providers: [
    Google({
      clientId: process.env.AUTH_GOOGLE_ID || '',
      clientSecret: process.env.AUTH_GOOGLE_SECRET || '',
      authorization: {
        params: {
          prompt: 'consent',
          access_type: 'offline',
          response_type: 'code',
        },
      },
    }),
    Credentials({
      name: 'Credentials',
      credentials: {
        email: { label: 'Email', type: 'text' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        await connectToDatabase();

        // Find user by email
        const user = await userTable.findOne({ email: credentials.email }).exec();

        if (!user) {
          throw new Error('No user found with the provided email');
        }

        // Check password (plain text comparison for simplicity)
        if (user.password && credentials.password !== user.password) {
          throw new Error('Invalid credentials');
        }

        // Set a new password if the old one is empty
        if (!user.password && credentials.password) {
          user.password = credentials.password;
          await user.save();
        }

        return {
          id: user._id.toString(),
          email: user.email,
          name: user.name,
        };
      },
    }),
  ],
  pages: {
    signIn: '/login',
    error: '/login',
  },
  callbacks: {
    async signIn({ profile }) {
      try {
        await connectToDatabase();

        if (profile) {
          let user = await userTable.findOne({ email: profile.email }).exec();

          if (!user) {
            // Create a new user if not found (set empty password for OAuth users)
            user = new userTable({
              name: profile.name,
              email: profile.email, // Password is not required for OAuth users
            });
            await user.save();
          }

          return true; // Proceed with sign-in
        }

        return true;
      } catch (error) {
        console.error('Error in signIn callback:', error);
        return false; // Deny sign-in if there's an error
      }
    },
    async session({ session, token }) {
      return {
        ...session,
        user: {
          ...session.user,
          id: token.id,
        },
      };
    },
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id;
        token.email = user.email;
      }
      return token;
    },
  },
});










