import { randomBytes } from "node:crypto";
import { argon2id, argon2Verify } from "hash-wasm";

/**
 * argon2id przez hash-wasm (czysty WASM, zero zaleznosci natywnych) -
 * dziala identycznie w kontenerze budowanym na dowolnej platformie, bez
 * node-gyp/kompilatora C++ w obrazie Dockera.
 */
export async function hashPassword(password: string, memoryKb: number): Promise<string> {
  const salt = randomBytes(16);
  return argon2id({
    password,
    salt,
    parallelism: 1,
    iterations: 3,
    memorySize: memoryKb,
    hashLength: 32,
    outputType: "encoded",
  });
}

export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  try {
    return await argon2Verify({ password, hash });
  } catch {
    return false;
  }
}
