# Ingress boundary

Local development uses the Next.js same-origin `/api` rewrite to the loopback NestJS service. No public reverse-proxy deployment exists yet. Production configuration must terminate HTTPS, preserve the configured browser origin and use a separate validated agent mTLS ingress. Review trusted proxy/IP handling before adding distributed rate limits.
