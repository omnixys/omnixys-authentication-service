import type { PhoneNumberInput } from '../inputs/phone-number.input.js';

export interface UserDTO extends UserUpdateDTO {
  username: string;
  phoneNumbers?: PhoneNumberInput[];
  invitationId?: string;
}

export interface UserUpdateDTO {
  id: string;
  firstName?: string;
  lastName?: string;
  email?: string;
}
