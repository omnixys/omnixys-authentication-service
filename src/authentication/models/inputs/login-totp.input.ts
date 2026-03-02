import { Field, InputType } from '@nestjs/graphql';
import { IsString } from 'class-validator';

@InputType()
export class LoginTotpInput {
  @Field()
  @IsString()
  username!: string;

  @Field()
  @IsString()
  code!: string;
}
