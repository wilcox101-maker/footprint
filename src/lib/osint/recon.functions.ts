import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

const schema = z.object({
  target: z.string().min(1).max(300),
  kind: z.enum(["domain", "email", "username", "ip", "url"]),
  modules: z.array(z.string().min(1).max(40)).min(1).max(8),
  authorized: z.boolean(),
  hibpKey: z.string().max(128).optional(),
  vtKey: z.string().max(128).optional(),
});

export const runModules = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    const parsed = schema.safeParse(input);
    if (!parsed.success) throw new Error("Check the target and try again.");
    return parsed.data;
  })
  .handler(async ({ data }) => {
    const { execute } = await import("./engine.server");
    return execute(data);
  });
