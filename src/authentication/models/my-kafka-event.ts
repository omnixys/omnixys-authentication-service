// src/kafka/types/my-kafka-event.ts

/**
 * Beschreibt den Standard-Aufbau eines Kafka-Events im Omnixys-Ökosystem.
 * Alle Events enthalten Metadaten und einen Nutzlast-Body.
 */
export interface MyKafkaEvent<TPayload = unknown> {
  /** Eindeutige Event-ID (z. B. UUID v4) */
  id: string;

  /** Der Event-Typ, z. B. "user.created", "authentcation.login", ... */
  type: string;

  /** Zeitstempel (ISO 8601) */
  timestamp: string;

  /** Service, der das Event gesendet hat (z. B. "omnixys-authentication") */
  source: string;

  /** Nutzlast mit beliebigem Typ */
  payload: TPayload;

  /** Optionaler Trace-Kontext für verteilte Tracing-Systeme */
  trace?: {
    traceId: string;
    spanId?: string;
  };
}

// // Beispiel: Authentifizierungs-Event
// export interface AuthLoginPayload {
//   userId: string;
//   username: string;
//   ipAddress: string;
// }

// export type AuthLoginEvent = MyKafkaEvent<AuthLoginPayload>;

// // Beispiel: User-Event
// export interface UserCreatedPayload {
//   userId: string;
//   email: string;
//   roles: string[];
// }

// export type UserCreatedEvent = MyKafkaEvent<UserCreatedPayload>;

// import { MyKafkaEvent, AuthLoginEvent } from './types/my-kafka-event.js';
// import { safeJsonParse } from '../utils/safe-json-parse.js';

// private async handleMessage(
//   topic: string,
//   partition: number,
//   message: KafkaMessage,
// ): Promise<void> {
//   const rawValue = message.value?.toString();
//   if (!rawValue) return;

//   // hier typsicher
//   const event = safeJsonParse<MyKafkaEvent>(rawValue);

//   this.logger.log(`Event ${event.type} von ${event.source}`);

//   await this.dispatcher.dispatch(topic, event, {
//     topic,
//     partition,
//     offset: message.offset,
//     headers: message.headers ?? {},
//     timestamp: message.timestamp ?? '',
//   });
// }
