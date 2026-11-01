import { BadRequestException } from '@nestjs/common';
import { z } from 'zod';

export const roles = ['OWNER', 'ADMIN', 'OPERATOR', 'VIEWER'] as const;
export type Role = typeof roles[number];
export const uuid = z.string().uuid();
export const name = z.string().trim().min(2).max(100);
export const email = z.string().trim().email().max(254).transform(value => value.toLowerCase());
export const password = z.string().min(12).max(128);
export function input<T>(schema: z.ZodType<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw new BadRequestException(result.error.issues.map(issue => `${issue.path.join('.') || 'input'}: ${issue.message}`).join('; '));
  return result.data;
}
