/** QuantumShield SDK — typed errors */

export class QuantumShieldError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number | null = null,
    public readonly body: Record<string, unknown> = {},
  ) {
    super(message);
    this.name = "QuantumShieldError";
  }
}

export class AuthenticationError    extends QuantumShieldError { name = "AuthenticationError";    }
export class AuthorizationError     extends QuantumShieldError { name = "AuthorizationError";     }
export class NotFoundError          extends QuantumShieldError { name = "NotFoundError";          }
export class ValidationError        extends QuantumShieldError { name = "ValidationError";        }
export class RateLimitError         extends QuantumShieldError { name = "RateLimitError";         }
export class ServerError            extends QuantumShieldError { name = "ServerError";            }
export class CANotInitialisedError  extends QuantumShieldError { name = "CANotInitialisedError";  }
export class CertVerificationError  extends QuantumShieldError { name = "CertVerificationError";  }
export class ReplayError            extends QuantumShieldError { name = "ReplayError";            }
export class ConnectionError        extends QuantumShieldError { name = "ConnectionError";        }

export function raiseForStatus(
  status: number,
  body:   Record<string, unknown>,
): never {
  const msg = (body["error"] as string | undefined) ?? `HTTP ${status}`;
  if (status === 400) throw new ValidationError(msg, status, body);
  if (status === 401) throw new AuthenticationError(msg, status, body);
  if (status === 403) throw new AuthorizationError(msg, status, body);
  if (status === 404) throw new NotFoundError(msg, status, body);
  if (status === 429) throw new RateLimitError(msg, status, body);
  if (status === 503) throw new CANotInitialisedError(msg, status, body);
  if (status >= 500)  throw new ServerError(msg, status, body);
  throw new QuantumShieldError(msg, status, body);
}
