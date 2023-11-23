import { ForbiddenException, Injectable } from '@nestjs/common';
import { User, Bookmark } from '@prisma/client';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) { }

  async signup(dto: AuthDto) {
    // generate pass hash
    const hash = await argon.hash(dto.password)
    // save user in db

    try {
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash
        },
        // Возвращаем только эти поля
        // select: {
        //   id: true,
        //   email: true,
        //   createdAt: true
        // }
      })
      
          delete user.hash;
          // return saved user
          return user;

    }
    catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if(error.code==='P2002') {
          throw new ForbiddenException('Credentials taken')
        }
      } else {
        throw error;
      }
    };
  }

  async signin(dto: AuthDto) {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email
      }
    })

    if(!user) throw new ForbiddenException('Credentials incorrect');

    const pwMatches = await argon.verify(user.hash, dto.password);

    if(!pwMatches) throw new ForbiddenException("Credentials incorrect");

    delete user.hash;

    return user;
  }
}
