import { env } from '../config/env.js';
import { PlatformTokenException } from './errors/platform-token.error.js';
import { Metadata } from '@grpc/grpc-js';
import { Inject, Injectable, OnModuleInit } from '@nestjs/common';
import { ClientGrpc } from '@nestjs/microservices';
import type {
  GetTenantRequest,
  GetTenantResponse,
  ListUserTenantsRequest,
  ListUserTenantsResponse,
  ValidateMembershipRequest,
  ValidateMembershipResponse,
} from '@omnixys/grpc-ts/types';
import { Observable, firstValueFrom } from 'rxjs';

type GrpcStubMethod<Req, Res> = (
  request: Req,
  metadata: Metadata,
) => Observable<Res>;

/**
 * gRPC-Stub für den TenantService (tenant-service), inklusive per-caller
 * Bearer-Authentifizierung über die grpc-Metadata (GrpcCallerGuard auf der
 * Server-Seite erwartet `authorization: Bearer <token>`).
 *
 * Der Stub wird über den global registrierten `GRPC_CLIENT` (GrpcClientModule
 * aus @omnixys/grpc-ts) erzeugt; NestJS gRPC-Clients akzeptieren Metadata als
 * zweites Argument jeder Service-Methode.
 */
export interface TenantServiceStub {
  getTenant: GrpcStubMethod<GetTenantRequest, GetTenantResponse>;
  validateMembership: GrpcStubMethod<
    ValidateMembershipRequest,
    ValidateMembershipResponse
  >;
  listUserTenants: GrpcStubMethod<
    ListUserTenantsRequest,
    ListUserTenantsResponse
  >;
}

@Injectable()
export class TenantGrpcService implements OnModuleInit {
  private service!: TenantServiceStub;

  constructor(@Inject('GRPC_CLIENT') private readonly client: ClientGrpc) {}

  onModuleInit(): void {
    this.service = this.client.getService<TenantServiceStub>('TenantService');
  }

  async validateMembership(
    request: ValidateMembershipRequest,
  ): Promise<ValidateMembershipResponse> {
    try {
      return await firstValueFrom(
        this.service.validateMembership(request, this.metadata()),
      );
    } catch (err) {
      throw new PlatformTokenException('tenant.validateMembership', err);
    }
  }

  async listUserTenants(
    request: ListUserTenantsRequest,
  ): Promise<ListUserTenantsResponse> {
    try {
      return await firstValueFrom(
        this.service.listUserTenants(request, this.metadata()),
      );
    } catch (err) {
      throw new PlatformTokenException('tenant.listUserTenants', err);
    }
  }

  private metadata(): Metadata {
    const metadata = new Metadata();
    metadata.set(
      'authorization',
      `Bearer ${env.TENANT_GRPC_AUTHENTICATION_TOKEN}`,
    );
    return metadata;
  }
}
