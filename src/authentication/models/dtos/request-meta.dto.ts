export interface RequestMeta {
  ip: string;
  userAgent?: string;
  requestId?: string;
  traceId?: string;
}

// @Mutation()
// async requestReset(
//   @Args('email') email: string,
//   @Context() ctx: GraphQLContext,
// ) {
//   const meta: RequestMeta = {
//     ip: ctx.req.ip,
//     userAgent: ctx.req.headers['user-agent'],
//   };

//   return this.resetService.requestReset(email, meta);
// }

// @Post('request')
// async requestReset(
//   @Body() dto: RequestResetDto,
//   @Req() req: Request,
// ) {
//   const meta: RequestMeta = {
//     ip: req.ip,
//     userAgent: req.headers['user-agent'],
//   };

//   return this.resetService.requestReset(dto.email, meta);
// }
