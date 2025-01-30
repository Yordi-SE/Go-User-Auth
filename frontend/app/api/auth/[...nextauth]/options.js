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
        console.log("credentials", `${process.env.NEXT_PUBLIC_API_BASE_URL}/api/auth/user/login`);
        try {
          if (credentials?.email && credentials?.password) {
            response = await axios.post(
              `http://app:8080/api/auth/user/login`,
              credentials,
              {
                headers: {
                  "Content-Type": "application/json",
                },
              }
            );
            if (response.data.data.two_factor_auth === true) {
              throw new Error("Two factor authentication is needed.:" + response.data.data.otp_token);
            }

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
                two_factor_auth: credentials.two_factor_auth,
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
                throw new Error("Bad Request: Missing or invalid data.");
              } else if (error.response.status === 401) {
                throw new Error("Unauthorized: Incorrect email or password.");
              } else if (error.response.status === 403) {
                throw new Error("Forbidden: Your account is inactive.");
              } else if (error.response.status === 500) {
                throw new Error("Server Error: Please try again later.");
              } else {
                throw new Error("An unexpected error occurred.");
              }
            } else if (error.request) {
              console.log("error", error.request);

              throw new Error("Request error: " + String(error.request));
            }
          } else {
            throw new Error(String(error.message));
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
