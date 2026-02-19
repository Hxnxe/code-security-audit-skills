# Supported Languages

- Python: Flask, Django, FastAPI, Tornado
- Java: Spring Boot, Struts, Servlet
- Go: Gin, Echo, net/http
- PHP: Laravel, ThinkPHP, raw PHP
- Node.js: Express, Koa, Fastify, Nitro/Nuxt, Next.js, SvelteKit, Remix

# Required Scan Surfaces

## Runtime Surfaces (mandatory)
- API routes / controllers / handlers
- Auth middleware, policy/guard modules
- DB wrappers and query helper modules

## Non-runtime Surfaces (mandatory)
- `seeders/*`
- `migrations/*`
- `*.sql`
- `.env*`
- `docker-compose*`
- deployment/runtime configs that may contain credentials
