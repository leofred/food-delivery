import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { LoginDto, RegisterDto } from './dto/user.dto';
import { PrismaService } from '../../../prisma/prisma.service';
import { Response } from 'express';
import * as bcrypt from 'bcrypt';

interface UserData {
  name: string;
  email: string;
  password: string;
  phone_number: number;
}
@Injectable()
export class UsersService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly prisma: PrismaService,
    private readonly configService: ConfigService,
  ) {}

  // register user
  async register(registerDto: RegisterDto, response: Response) {
    const { name, email, password, phone_number } = registerDto;
    const isEmailExist = await this.prisma.user.findUnique({
      where: { email },
    });

    if (isEmailExist) {
      throw new BadRequestException('User already exist with this email!');
    }
    const isPhoneNumberExist = await this.prisma.user.findUnique({
      where: { phone_number },
    });

    if (isPhoneNumberExist) {
      throw new BadRequestException(
        'User already exist with this phone number!',
      );
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
      name,
      email,
      password: hashedPassword,
      phone_number,
    };

    const { activationCode } = await this.createActivationToken(user);

    console.log('activationCode', activationCode);

    return { user, response };
  }

  // create activation token
  async createActivationToken(user: UserData) {
    const activationCode = Math.floor(100000 + Math.random() * 9000);

    const token = await this.jwtService.sign(
      {
        user,
        activationCode,
      },
      {
        secret: this.configService.get<string>('ACTIVATION_SECRET'),
        expiresIn: '10m',
      },
    );
    return { token, activationCode };
  }

  // login user
  async Login(loginDto: LoginDto /*, response: Response*/) {
    const { email, password } = loginDto;
    const user = {
      email,
      password,
    };
    return user;
  }

  async getUsers() {
    return this.prisma.user.findMany({});
  }
}
