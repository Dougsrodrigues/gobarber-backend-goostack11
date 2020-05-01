import { getRepository } from 'typeorm';
import { compare } from 'bcryptjs';
import { sign } from 'jsonwebtoken';

import authCondig from '../config/auth';
import AppError from '../errors/AppError';

import User from '../models/User';

interface Request {
  email: string;
  password: string;
}

interface Response {
  user: User;
  token: string;
}

class AuthenticateUserService {
  public async execute({ email, password }: Request): Promise<Response> {
    const userRepository = getRepository(User);

    const user = await userRepository.findOne({ where: { email } });

    if (!user) {
      throw new AppError('Incorrect email/password combination', 401);
    }

    //comparando senha não criptografada com a criptografada
    const passwordMatch = await compare(password, user.password);

    if (!passwordMatch) {
      throw new AppError('Incorrect email/password combination', 401);
    }

    //Usuario autenticado
    const { secret, expiresIn } = authCondig.jwt;

    const token = sign({}, secret, {
      subject: user.id,
      expiresIn: expiresIn,
    });

    return {
      user,
      token,
    };
  }
}

export default AuthenticateUserService;
