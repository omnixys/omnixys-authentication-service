import type { PhoneNumberInput } from '../inputs/phone-number.input.js';

export interface UserDTO {
  id: string;
  firstName: string;
  lastName: string;
  email?: string;
  phoneNumbers?: PhoneNumberInput[];
  invitationId?: string;
}
