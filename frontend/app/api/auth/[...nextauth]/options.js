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
        let response;
        try {
          if (credentials?.email && credentials?.password) {
            response = await axios.post(
              `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/auth/user/login`,
              credentials
            );

            if (response.status === 200) {
              return response.data.data;
            }
          } else {
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
                refresh_token: credentials.refresh_token,
              };
              return user;
            }
            throw new Error("Invalid credentials or session");
          }
        } catch (error) {
          if (axios.isAxiosError(error)) {
            if (error.response) {
              console.log("error", error.response.data);
              if (
                error.response.data.error.message ==
                "Email address is not verified."
              ) {
                throw new Error("Email address is not verified.");
              } else if (error.response.status === 400) {
                setError("Bad Request: Missing or invalid data.");
              } else if (error.response.status === 401) {
                setError("Unauthorized: Incorrect email or password.");
              } else if (error.response.status === 403) {
                setError("Forbidden: Your account is inactive.");
              } else if (error.response.status === 500) {
                setError("Server Error: Please try again later.");
              } else {
                setError("An unexpected error occurred.");
              }
            } else if (error.request) {
              setError("Network error: Unable to reach the server.");
            }
          } else {
            setError("Unexpected error: " + String(error));
          }
        }
        return null;
      },
    }),
  ],
  session: {
    strategy: "jwt",
    maxAge: 3 * 24 * 60 * 60,
  },
  jwt: {
    maxAge: 3 * 24 * 60 * 60,
  },
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.userData = user;
      }
      return token;
    },
    async session({ session, token }) {
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
