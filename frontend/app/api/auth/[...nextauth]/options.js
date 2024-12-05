import CredentialsProvider from "next-auth/providers/credentials";
import axios from "axios";
import { jwtDecode } from "jwt-decode";

export const options = {
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        email: {
          label: "email:",
          type: "text",
          placeholder: "your-email",
        },
        password: {
          label: "password:",
          type: "password",
          placeholder: "your-password",
        },
      },
      async authorize(credentials) {
        if (credentials?.email && credentials?.password) {
          return credentials;
        } else {
          console.log(credentials.user);
          if (credentials?.access_token) {
            const user = {
              access_token: credentials.access_token,
              full_name: credentials.full_name,
              email: credentials.email,
              profile_image: credentials.profile_image,
              phone_number: credentials.phone_number,
              user_id: credentials.user_id,
              role: credentials.role,
              is_verified: credentials.is_verified,
            };
            return user;
          }
          throw new Error("Invalid credentials or session");
        }

        return null;
      },
    }),
  ],
  session: {
    strategy: "jwt",
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.userData = user;
      }
      return token;
    },
    async session({ session, token }) {
      const getExpiration = (token) => {
        try {
          const decoded = jwtDecode(token);
          if (!decoded.exp) {
            return null;
          }
          return decoded.exp * 1000;
        } catch {
          return null;
        }
      };

      const refreshExpiration = getExpiration(token.userData.refresh_token);

      if (refreshExpiration) {
        session.expires = new Date(refreshExpiration).toISOString();
      }
      session.user = token.userData;
      return session;
    },
  },
  pages: {
    signIn: "/auth/login",
    signOut: "/auth/logout",
    newUser: "/auth/signup",
  },
};
