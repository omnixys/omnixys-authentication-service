export const ValkeyKey = {
  seatLock: (seatId: string) => `seat:lock:${seatId}`,
  invitation: (id: string) => `inv:${id}`,
  pendingContact: (id: string) => `inv:pending:${id}`,
  rsvpRateLimit: (guestId: string) => `rsvp:limit:${guestId}`,
  webauthnRegChallenge: (userId: string) => `webauthn:reg:${userId}`,
  webauthnAuthChallenge: (userId: string) => `webauthn:auth:${userId}`,
  magicLinkToken: (token: string) => `auth:magic:${token}`,
  webauthnGlobalAuthChallenge: (challenge: string) =>
    `webauthn:auth:${challenge}`,
} as const;
