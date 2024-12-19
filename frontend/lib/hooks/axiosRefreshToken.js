"use client";

import axiosInst from "../axios";
import axios from "axios";
import { signIn, useSession, signOut } from "next-auth/react";

export const useRefreshToken = () => {
  const { data: session } = useSession();

  const refreshToken = async () => {
    try {
      console.log("session?.user?.refresh_token", session?.user?.refresh_token);
      const res = await axiosInst.post(
        "/api/auth/user/refresh",
        {
          refresh_token: session?.user?.refresh_token,
        },
        {
          withCredentials: true,
        }
      );

      if (session) {
        session.user.access_token = res.data.access_token;
        session.user.refresh_token = res.data.refresh_token;
      } else signIn();
    } catch (error) {
      if (axios.isAxiosError(error)) {
        if (error.response?.status === 401) {
          await signOut({
            callbackUrl: "/auth/login",
          });
          alert("Session expired. Please log in again.");
        } else {
          alert(
            "An error occurred while refreshing the session. Please try again."
          );
        }
      } else {
        alert("An unexpected error occurred.");
      }
    }
  };

  return refreshToken;
};
