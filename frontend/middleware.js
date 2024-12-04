import { withAuth } from "next-auth/middleware";
import { NextRequest, NextResponse } from "next/server";

export default withAuth(
  // `withAuth` augments your `Request` with the user's token.
  function middleware(req) {
    if (
      (req.nextUrl.pathname == "/" ||
        req.nextUrl.pathname == "/dashboard" ||
        req.nextUrl.pathname == "/cart") &&
      req.nextauth.token?.userData?.role == false
    )
      return NextResponse.rewrite(
        new URL("/auth/login?message=You Are Not Authorized!", req.url)
      );
  },
  {
    callbacks: {
      authorized: ({ token }) => !!token,
    },
  }
);
export const config = {
  matcher: ["/", "/dashboard", "/cart", "/home"],
};
