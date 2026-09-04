import { env } from '../../config/env.js';
import * as grpc from '@grpc/grpc-js';
import * as protoLoader from '@grpc/proto-loader';
import { Injectable, OnModuleInit } from '@nestjs/common';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

interface CreateMembershipRequest {
  tenantId: string;
  userId: string;
  role: string;
  status: string;
  createdBy: string;
}

interface TenantServiceClient extends grpc.Client {
  CreateMembership?: (
    request: CreateMembershipRequest,
    metadata: grpc.Metadata,
    callback: (error: grpc.ServiceError | null, response?: unknown) => void,
  ) => void;
}

@Injectable()
export class TenantMembershipClient implements OnModuleInit {
  private createMembership!: (
    request: CreateMembershipRequest,
    metadata: grpc.Metadata,
  ) => Promise<unknown>;

  async onModuleInit(): Promise<void> {
    const protoPath = fileURLToPath(
      import.meta.resolve('@omnixys/grpc-ts/proto/tenant.proto'),
    );
    const packageDefinition = protoLoader.loadSync(protoPath, {
      keepCase: false,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true,
    });
    const proto = grpc.loadPackageDefinition(packageDefinition) as {
      omnixys?: {
        tenant?: {
          TenantService: new (
            url: string,
            credentials: grpc.ChannelCredentials,
          ) => TenantServiceClient;
        };
      };
    };
    const TenantServiceClient = proto.omnixys?.tenant?.TenantService;
    if (!TenantServiceClient) {
      throw new Error(
        'Failed to load gRPC TenantService client from tenant proto',
      );
    }

    const client = new TenantServiceClient(
      env.TENANT_SERVICE_URL,
      grpc.credentials.createInsecure(),
    );
    if (!client.CreateMembership) {
      throw new Error('TenantService client does not expose CreateMembership');
    }
    this.createMembership = promisify(client.CreateMembership.bind(client));
  }

  async provisionMember(tenantId: string, userId: string): Promise<void> {
    const metadata = new grpc.Metadata();
    metadata.set(
      'authorization',
      `Bearer ${env.TENANT_GRPC_AUTHENTICATION_TOKEN}`,
    );

    await this.createMembership(
      {
        tenantId,
        userId,
        role: 'MEMBER',
        status: 'ACTIVE',
        createdBy: userId,
      },
      metadata,
    );
  }
}
