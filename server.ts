import { serve } from 'https://deno.land/std@v0.42.0/http/server.ts';

const PORT = Number(Deno.env.get('PORT')) || 8080;

const s = serve({ port: PORT });

console.log(`http://localhost:${PORT}/`);

for await (const req of s) {
  const headers = new Headers();
  headers.set('Content-Type', 'application/json');
  req.respond({ body: JSON.stringify(req), headers });
}
