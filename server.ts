import {
  Application,
  Router,
} from "https://deno.land/x/oak/mod.ts";
const PORT = Number(Deno.env.get("PORT")) || 8080;

const app = new Application();

// Logger
app.use(async (ctx, next) => {
  await next();
  const rt = ctx.response.headers.get("X-Response-Time");
  console.log(
    `${ctx.request.method} ${ctx.request.url} - ${rt}`,
  );
});

// Timing
app.use(async (ctx, next) => {
  const start = Date.now();
  await next();
  const ms = Date.now() - start;
  ctx.response.headers.set("X-Response-Time", `${ms}ms`);
});
const router = new Router();
router.get("/ping", async (ctx) => {
  const body = await ctx.request.body();
  console.log(body?.value);

  ctx.response.body = body;
});

app.use(router.routes());
app.use(router.allowedMethods());
app.use((ctx) => {
  // ctx.throw(404);
  ctx.response.status = 404;
  ctx.response.body = 404;
});
await app.listen({ port: PORT });
