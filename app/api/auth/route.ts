import { getUserByEmail } from "@/data/user";
import { NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import { db } from "@/lib/db";
import { generateVerificationToken } from "@/lib/token";
import { sendVerificationEmail } from "@/lib/mails";

export async function POST(
    req: Request,
) {
    try {
    
    const body = await req.json();
    
    const { email, password, name } =  body;

    if (!name) {
        return new NextResponse("Name is required", { status: 400 });
      }
    
    if (!email) {
        return new NextResponse("Email is required", { status: 400 });
      }
    if (!password) {
        return new NextResponse("Paword is required", { status: 400 });
      }
    
    const hashedPassword = await bcrypt.hash(password, 10);

    const existingUser = await getUserByEmail(email);
    
    if (existingUser) {
        return new NextResponse("Email já em uso!", { status: 403 });
    }
    
    const user = await db.user.create({
        data: {
            name,
            email,
            password: hashedPassword
        }
    })

    const verificationToken = await generateVerificationToken(email);
    await sendVerificationEmail(
        verificationToken.email,
        verificationToken.token,
        name
      );

    return NextResponse.json("Email de confirmação foi enviado!");

} catch (e: any) {
    return new NextResponse(e.message, {status: 402});
}
}

/*
import { NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs';

import prismadb from '@/lib/prismadb';

export async function POST(
  req: Request,
) {
  try {
    const { userId } = auth();
    const body = await req.json();

    const { name } = body;

    if (!userId) {
      return new NextResponse("Unauthorized", { status: 403 });
    }

    if (!name) {
      return new NextResponse("Name is required", { status: 400 });
    }

    const store = await prismadb.store.create({
      data: {
        name,
        userId,
      }
    });
  
    return NextResponse.json(store);
  } catch (error) {
    console.log('[STORES_POST]', error);
    return new NextResponse("Internal error", { status: 500 });
  }
};

*/